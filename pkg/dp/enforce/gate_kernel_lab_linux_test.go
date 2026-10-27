// SPDX-License-Identifier: Apache-2.0
//go:build linux

package enforce

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"

	"github.com/tonylturner/containd/pkg/dp/rules"
)

// gateLab is the topology the gate kernel tests route through this
// namespace, which stands in for containd: a client namespace behind gs0
// (zone client), a bridged LAN gsbr (zone lan) holding the server and a
// second host, and a WAN namespace behind gs2 (zone wan). It runs only when
// CONTAIND_NETNS_KERNEL_TEST=1 inside a disposable Linux container with
// NET_ADMIN, NET_RAW and SYS_ADMIN, nft, iproute2 and Python; see
// scripts/gate-kernel-tests.sh.
type gateLab struct {
	ctx                          context.Context
	client, server, hairpin, wan string
}

const (
	gateClientV4     = "198.18.50.2"
	gateClientV6     = "fd18:50::2"
	gateClientRouter = "198.18.50.1"
	gateServerV4     = "198.18.60.2"
	gateServerV6     = "fd18:60::2"
	gateLANRouter    = "198.18.60.1"
	gateLANRouterV6  = "fd18:60::1"
	gateHairpinV4    = "198.18.60.3"
	gateWANHostV4    = "198.18.70.2"
	gateWANRouter    = "198.18.70.1"
	gateForwardPort  = 18000
	gateRouteTable   = 104010
)

func newGateLab(t *testing.T) *gateLab {
	t.Helper()
	if os.Getenv("CONTAIND_NETNS_KERNEL_TEST") != "1" || os.Geteuid() != 0 {
		t.Skip("requires CONTAIND_NETNS_KERNEL_TEST=1 in a disposable Linux container with NET_ADMIN, NET_RAW and SYS_ADMIN; see scripts/gate-kernel-tests.sh")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 240*time.Second)
	t.Cleanup(cancel)
	lab := &gateLab{ctx: ctx, client: "gsclient", server: "gsserver", hairpin: "gshair", wan: "gswan"}
	t.Logf("kernel %s, %s", lab.run(t, "uname", "-r"), lab.run(t, "nft", "--version"))
	// /proc/sys is read-only in an unprivileged container: the runner sets
	// these with docker run --sysctl.
	for _, s := range []string{"net/ipv4/ip_forward", "net/ipv6/conf/all/forwarding", "net/ipv4/conf/all/rp_filter", "net/ipv4/conf/default/rp_filter"} {
		lab.requireSysctl(t, s, "1")
	}
	for _, s := range []string{"net/bridge/bridge-nf-call-iptables", "net/bridge/bridge-nf-call-ip6tables", "net/ipv4/tcp_fwmark_accept"} {
		lab.requireSysctl(t, s, "0")
	}
	lab.run(t, "ip", "link", "add", "gsbr", "type", "bridge")
	t.Cleanup(func() { lab.run(t, "ip", "link", "del", "gsbr") })
	lab.run(t, "ip", "addr", "add", gateLANRouter+"/24", "dev", "gsbr")
	lab.run(t, "ip", "-6", "addr", "add", gateLANRouterV6+"/64", "dev", "gsbr", "nodad")
	lab.run(t, "ip", "link", "set", "gsbr", "up")
	type leaf struct {
		ns, dev, peer, host4, host6, addr4, addr6, gw4, gw6, master string
	}
	for _, l := range []leaf{
		{lab.client, "gs0", "gsp0", gateClientRouter + "/24", "fd18:50::1/64", gateClientV4 + "/24", gateClientV6 + "/64", gateClientRouter, "fd18:50::1", ""},
		{lab.server, "gs1", "gsp1", "", "", gateServerV4 + "/24", gateServerV6 + "/64", gateLANRouter, gateLANRouterV6, "gsbr"},
		{lab.hairpin, "gs3", "gsp3", "", "", gateHairpinV4 + "/24", "", gateLANRouter, "", "gsbr"},
		{lab.wan, "gs2", "gsp2", gateWANRouter + "/24", "", gateWANHostV4 + "/24", "", gateWANRouter, "", ""},
	} {
		lab.run(t, "ip", "netns", "add", l.ns)
		t.Cleanup(func() { lab.run(t, "ip", "netns", "del", l.ns) })
		lab.run(t, "ip", "link", "add", l.dev, "type", "veth", "peer", "name", l.peer)
		t.Cleanup(func() { lab.run(t, "ip", "link", "del", l.dev) })
		lab.run(t, "ip", "link", "set", l.peer, "netns", l.ns)
		if l.master != "" {
			lab.run(t, "ip", "link", "set", l.dev, "master", l.master)
		}
		if l.host4 != "" {
			lab.run(t, "ip", "addr", "add", l.host4, "dev", l.dev)
		}
		if l.host6 != "" {
			lab.run(t, "ip", "-6", "addr", "add", l.host6, "dev", l.dev, "nodad")
		}
		lab.run(t, "ip", "link", "set", l.dev, "up")
		lab.run(t, "ip", "-n", l.ns, "addr", "add", l.addr4, "dev", l.peer)
		lab.run(t, "ip", "-n", l.ns, "link", "set", l.peer, "up")
		lab.run(t, "ip", "-n", l.ns, "link", "set", "lo", "up")
		lab.run(t, "ip", "-n", l.ns, "route", "add", "default", "via", l.gw4)
		if l.addr6 != "" {
			lab.run(t, "ip", "-n", l.ns, "-6", "addr", "add", l.addr6, "dev", l.peer, "nodad")
			lab.run(t, "ip", "-n", l.ns, "-6", "route", "add", "default", "via", l.gw6)
		}
	}
	for _, dev := range []string{"gs0", "gs2", "gsbr"} {
		lab.requireSysctl(t, "net/ipv4/conf/"+dev+"/rp_filter", "1")
	}
	// Routing neighbours the gate must coexist with: a management pin at
	// priority 1 for a client that may also manage containd, and a user
	// policy rule at priority 2 that routes the client's traffic to the LAN
	// through its own table. The gate's local rule precedes the latter.
	lab.run(t, "ip", "route", "add", gateClientV4+"/32", "dev", "gs0", "table", "104000")
	lab.run(t, "ip", "rule", "add", "priority", "1", "from", gateClientRouter, "to", gateClientV4, "lookup", "104000")
	lab.run(t, "ip", "route", "add", "198.18.60.0/24", "dev", "gsbr", "table", "201")
	lab.run(t, "ip", "rule", "add", "priority", "2", "from", "198.18.50.0/24", "to", "198.18.60.0/24", "lookup", "201")
	t.Cleanup(func() {
		lab.run(t, "ip", "rule", "del", "priority", "2", "from", "198.18.50.0/24", "to", "198.18.60.0/24", "lookup", "201")
		lab.run(t, "ip", "rule", "del", "priority", "1", "from", gateClientRouter, "to", gateClientV4, "lookup", "104000")
	})
	// The policy route of GateLocalPktMark, which the gate manager owns in
	// the product.
	for _, family := range []string{"-4", "-6"} {
		mark := fmt.Sprintf("0x%08x/0x%08x", GateLocalPktMark, GateLocalPktMark)
		lab.run(t, "ip", family, "rule", "add", "priority", "1", "fwmark", mark, "lookup", strconv.Itoa(gateRouteTable))
		lab.run(t, "ip", family, "route", "add", "local", "default", "dev", "lo", "table", strconv.Itoa(gateRouteTable))
		t.Cleanup(func() {
			lab.run(t, "ip", family, "rule", "del", "priority", "1", "fwmark", mark, "lookup", strconv.Itoa(gateRouteTable))
			lab.run(t, "ip", family, "route", "flush", "table", strconv.Itoa(gateRouteTable))
		})
	}
	return lab
}

func (l *gateLab) run(t *testing.T, args ...string) string {
	t.Helper()
	out, err := exec.CommandContext(l.ctx, args[0], args[1:]...).CombinedOutput()
	if err != nil {
		t.Fatalf("%v: %v: %s", args, err, out)
	}
	return strings.TrimSpace(string(out))
}

func (l *gateLab) requireSysctl(t *testing.T, path, value string) {
	t.Helper()
	data, err := os.ReadFile("/proc/sys/" + path)
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.TrimSpace(string(data)); got != value {
		t.Fatalf("%s is %q, want %q (set it with docker run --sysctl)", path, got, value)
	}
}

// nftIn loads an nft script in namespace ns ("" is this namespace).
func (l *gateLab) nftIn(t *testing.T, ns, script string) {
	t.Helper()
	args := []string{"nft", "-f", "-"}
	if ns != "" {
		args = append([]string{"ip", "netns", "exec", ns}, args...)
	}
	cmd := exec.CommandContext(l.ctx, args[0], args[1:]...)
	cmd.Stdin = strings.NewReader(script)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("nft: %v: %s\n%s", err, out, script)
	}
}

// install compiles snap with c and installs it as the engine does,
// converging the live dynamic table over whatever a previous install left.
// The tables are removed when the calling (sub)test ends.
func (l *gateLab) install(t *testing.T, c *Compiler, snap *rules.Snapshot) {
	t.Helper()
	text, err := c.CompileFirewall(snap)
	if err != nil {
		t.Fatal(err)
	}
	live, err := NewNftApplier().ReadTable(l.ctx, c.DynamicTable())
	if err != nil {
		t.Fatal(err)
	}
	if err := NewNftApplier().Apply(l.ctx, c.InstallScript(live, "", text)); err != nil {
		t.Fatalf("%v\n%s", err, text)
	}
	t.Cleanup(func() { l.uninstall(t) })
}

// uninstall removes containd's tables, present or not.
func (l *gateLab) uninstall(t *testing.T) {
	t.Helper()
	l.nftIn(t, "", NewCompiler().DeleteTables())
}

var gateCounterPackets = regexp.MustCompile(`packets (\d+)`)

// counter reads a named nft counter in namespace ns ("" is this namespace).
func (l *gateLab) counter(t *testing.T, ns, table, name string) uint64 {
	t.Helper()
	args := []string{"nft", "list", "counter", "inet", table, name}
	if ns != "" {
		args = append([]string{"ip", "netns", "exec", ns}, args...)
	}
	m := gateCounterPackets.FindStringSubmatch(l.run(t, args...))
	if m == nil {
		t.Fatalf("counter %s/%s not listed", table, name)
	}
	n, err := strconv.ParseUint(m[1], 10, 64)
	if err != nil {
		t.Fatal(err)
	}
	return n
}

const gateServerProgram = `import socket, sys
addr, port = sys.argv[1], int(sys.argv[2])
s = socket.socket(socket.AF_INET6 if ':' in addr else socket.AF_INET)
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind((addr, port)); s.listen(); print('ready', flush=True)
while True:
    c, a = s.accept()
    line = c.makefile('rb').readline().decode().rstrip('\n')
    c.sendall(('peer=%s msg=%s\n' % (a[0], line)).encode()); c.close()
`

// serve runs a line server in namespace ns on addr:port that answers each
// line with the peer address it saw and the line. It lives until the test
// that started it ends.
func (l *gateLab) serve(t *testing.T, ns, addr string, port int) {
	t.Helper()
	server := exec.CommandContext(l.ctx, "ip", "netns", "exec", ns, "python3", "-u", "-c", gateServerProgram, addr, strconv.Itoa(port))
	stdout, err := server.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	server.Stderr = os.Stderr
	if err := server.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = server.Process.Kill(); _ = server.Wait() })
	if !bufio.NewScanner(stdout).Scan() {
		t.Fatal("server did not start")
	}
}

// serveLocal runs the same line server in this namespace with Go, tagging
// its answers "local": it stands in for management.
func (l *gateLab) serveLocal(t *testing.T, addr string, port int) {
	t.Helper()
	ln, err := net.Listen("tcp4", net.JoinHostPort(addr, strconv.Itoa(port)))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				line, _ := bufio.NewReader(c).ReadString('\n')
				host, _, _ := net.SplitHostPort(c.RemoteAddr().String())
				fmt.Fprintf(c, "peer=%s msg=local %s\n", host, strings.TrimSuffix(line, "\n"))
			}()
		}
	}()
}

const gateClientProgram = `import socket, sys
host, port = sys.argv[1], int(sys.argv[2])
s = socket.socket(socket.AF_INET6 if ':' in host else socket.AF_INET)
s.settimeout(4)
try:
    s.connect((host, port))
except OSError as e:
    print('error', e.errno, flush=True); sys.exit(0)
print('connected', s.getsockname()[1], flush=True)
data = b''
try:
    s.sendall(sys.stdin.readline().encode())
    while not data.endswith(b'\n'):
        chunk = s.recv(4096)
        if not chunk:
            break
        data += chunk
except OSError as e:
    print('error', e.errno, flush=True); sys.exit(0)
print('reply', data.decode().rstrip('\n'), flush=True)
`

// gateClient is one TCP connection held open by a Python process in a
// namespace: it connects first and sends its line only on exchange.
type gateClient struct {
	stdin io.WriteCloser
	out   *bufio.Scanner
	port  string // local port when connected
	err   string // "error <errno>" when the connect failed
}

// connect opens a connection from ns to addr:port. A failed connect
// reports its errno; a connect that times out reports "error None".
func (l *gateLab) connect(t *testing.T, ns, addr string, port int) *gateClient {
	t.Helper()
	cmd := exec.CommandContext(l.ctx, "ip", "netns", "exec", ns, "python3", "-u", "-c", gateClientProgram, addr, strconv.Itoa(port))
	stdin, err := cmd.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = cmd.Process.Kill(); _ = cmd.Wait() })
	c := &gateClient{stdin: stdin, out: bufio.NewScanner(stdout)}
	if !c.out.Scan() {
		t.Fatalf("client %s -> %s:%d produced no output", ns, addr, port)
	}
	line := c.out.Text()
	switch {
	case strings.HasPrefix(line, "connected "):
		c.port = strings.TrimPrefix(line, "connected ")
	case strings.HasPrefix(line, "error "):
		c.err = line
	default:
		t.Fatalf("client: %q", line)
	}
	return c
}

// exchange sends line and returns the server's answer: "" at EOF, or
// "error <errno>" when the connection failed ("error None": timed out).
func (c *gateClient) exchange(t *testing.T, line string) string {
	t.Helper()
	if c.err != "" {
		t.Fatalf("exchange on failed connection: %s", c.err)
	}
	if _, err := io.WriteString(c.stdin, line+"\n"); err != nil {
		t.Fatal(err)
	}
	if !c.out.Scan() {
		t.Fatal("client produced no reply line")
	}
	return strings.TrimPrefix(c.out.Text(), "reply ")
}

// exchange connects from ns to addr:port, sends line and returns the
// connection's local port and the answer.
func (l *gateLab) exchange(t *testing.T, ns, addr string, port int, line string) (string, string) {
	t.Helper()
	c := l.connect(t, ns, addr, port)
	if c.err != "" {
		t.Fatalf("connect %s -> %s:%d: %s", ns, addr, port, c.err)
	}
	return c.port, c.exchange(t, line)
}

// gateProxy is the transparent proxy in this namespace, standing in for
// the gate manager: it listens on both loopback listener ports, dials the
// accepted local address with the client's address and the upstream socket
// mark the ABI prescribes, and prefixes the forwarded line with "via-gate"
// so that a server's answer shows the path it took. In hold mode it
// answers "hello" by itself, once released, without dialing.
type gateProxy struct {
	lab     *gateLab
	hold    bool
	release chan struct{}
	mu      sync.Mutex
	accepts map[string]gateAccept // by client address
	total   int
}

type gateAccept struct {
	local, original string
	masq            bool   // accepted on the masquerading listener
	dial            string // upstream dial error
}

func startGateProxy(t *testing.T, lab *gateLab) *gateProxy {
	t.Helper()
	g := &gateProxy{lab: lab, accepts: map[string]gateAccept{}, release: make(chan struct{})}
	for _, l := range []struct {
		network, addr string
		port          uint16
		masq          bool
	}{
		{"tcp4", "127.0.0.1", DefaultGatePlainPort, false}, {"tcp6", "::1", DefaultGatePlainPort, false},
		{"tcp4", "127.0.0.1", DefaultGateMasqPort, true}, {"tcp6", "::1", DefaultGateMasqPort, true},
	} {
		lc := net.ListenConfig{Control: func(network, _ string, c syscall.RawConn) error { return gateSocketControl(c, network, 0) }}
		ln, err := lc.Listen(lab.ctx, l.network, net.JoinHostPort(l.addr, strconv.Itoa(int(l.port))))
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { ln.Close() })
		go func(network string, masq bool) {
			for {
				c, err := ln.Accept()
				if err != nil {
					return
				}
				go g.handle(network, c.(*net.TCPConn), masq)
			}
		}(l.network, l.masq)
	}
	return g
}

// gateSocketControl makes the socket transparent for its family and marks
// it.
func gateSocketControl(c syscall.RawConn, network string, mark int) error {
	var serr error
	err := c.Control(func(fd uintptr) {
		if network == "tcp6" {
			serr = unix.SetsockoptInt(int(fd), unix.SOL_IPV6, unix.IPV6_TRANSPARENT, 1)
		} else {
			serr = unix.SetsockoptInt(int(fd), unix.SOL_IP, unix.IP_TRANSPARENT, 1)
		}
		if serr == nil && mark != 0 {
			serr = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_MARK, mark)
		}
	})
	if err != nil {
		return err
	}
	return serr
}

func (g *gateProxy) handle(network string, c *net.TCPConn, masq bool) {
	defer c.Close()
	client := c.RemoteAddr().(*net.TCPAddr)
	a := gateAccept{local: c.LocalAddr().String(), original: gateOriginalDst(c, network), masq: masq}
	g.mu.Lock()
	g.total++
	hold, release := g.hold, g.release
	g.mu.Unlock()
	if hold {
		g.record(client, a)
		<-release
		_, _ = io.WriteString(c, "hello\n")
		return
	}
	up, err := g.dial(network, client, a, masq)
	if err != nil {
		a.dial = err.Error()
	}
	g.record(client, a)
	if err != nil {
		return
	}
	defer up.Close()
	line, err := bufio.NewReader(c).ReadString('\n')
	if err != nil {
		return
	}
	if _, err := io.WriteString(up, "via-gate "+line); err != nil {
		return
	}
	reply, _ := bufio.NewReader(up).ReadString('\n')
	_, _ = io.WriteString(c, reply)
}

// dial opens the upstream leg: transparent, bound to the client's address
// on a port other than the client's (two legs on one port would share a
// conntrack entry), marked GateUpstreamSockMark, plus GateMasqSockMark for
// a client of the masquerading listener.
func (g *gateProxy) dial(network string, client *net.TCPAddr, a gateAccept, masq bool) (net.Conn, error) {
	mark := int(GateUpstreamSockMark)
	if masq {
		mark |= int(GateMasqSockMark)
	}
	for _, port := range []int{0, client.Port + 1} {
		d := net.Dialer{Timeout: 3 * time.Second, LocalAddr: &net.TCPAddr{IP: client.IP, Port: port},
			Control: func(network, _ string, rc syscall.RawConn) error { return gateSocketControl(rc, network, mark) }}
		up, err := d.DialContext(g.lab.ctx, network, a.local)
		if err != nil {
			return nil, err
		}
		if up.LocalAddr().(*net.TCPAddr).Port != client.Port {
			return up, nil
		}
		up.Close()
	}
	return nil, fmt.Errorf("upstream port equals the client port %d", client.Port)
}

func (g *gateProxy) record(client *net.TCPAddr, a gateAccept) {
	g.mu.Lock()
	g.accepts[client.String()] = a
	g.mu.Unlock()
}

// gateOriginalDst returns the connection's destination before DNAT from
// connection tracking (SO_ORIGINAL_DST), or the error.
func gateOriginalDst(c *net.TCPConn, network string) string {
	raw, err := c.SyscallConn()
	if err != nil {
		return err.Error()
	}
	var result string
	if err := raw.Control(func(fd uintptr) {
		level, addr := uintptr(unix.SOL_IP), ""
		var sa unsafe.Pointer
		var n uint32
		var sa4 unix.RawSockaddrInet4
		var sa6 unix.RawSockaddrInet6
		if network == "tcp6" {
			level, sa, n = unix.SOL_IPV6, unsafe.Pointer(&sa6), uint32(unsafe.Sizeof(sa6))
		} else {
			sa, n = unsafe.Pointer(&sa4), uint32(unsafe.Sizeof(sa4))
		}
		if _, _, e := unix.Syscall6(unix.SYS_GETSOCKOPT, fd, level, unix.SO_ORIGINAL_DST, uintptr(sa), uintptr(unsafe.Pointer(&n)), 0); e != 0 {
			result = "getsockopt: " + e.Error()
			return
		}
		var port uint16
		if network == "tcp6" {
			addr, port = net.IP(sa6.Addr[:]).String(), sa6.Port
		} else {
			addr, port = net.IP(sa4.Addr[:]).String(), sa4.Port
		}
		result = net.JoinHostPort(addr, strconv.Itoa(int(port>>8|(port&0xff)<<8)))
	}); err != nil {
		return err.Error()
	}
	return result
}

// accepted returns the proxy's record for the client address, waiting
// briefly for the handler to store it, and requires its upstream dial to
// have succeeded.
func (g *gateProxy) accepted(t *testing.T, client string) gateAccept {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for {
		if a := g.find(client); a != nil {
			if a.dial != "" {
				t.Fatalf("gate accepted %s but the upstream dial failed: %s", client, a.dial)
			}
			return *a
		}
		if time.Now().After(deadline) {
			t.Fatalf("gate did not accept a connection from %s", client)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func (g *gateProxy) find(client string) *gateAccept {
	g.mu.Lock()
	defer g.mu.Unlock()
	if a, ok := g.accepts[client]; ok {
		return &a
	}
	return nil
}

// count is the number of connections accepted so far.
func (g *gateProxy) count() int {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.total
}

// holding puts the proxy in hold mode until the returned release is
// called, which also lets every held connection answer.
func (g *gateProxy) holding() (release func()) {
	g.mu.Lock()
	g.hold = true
	g.mu.Unlock()
	var once sync.Once
	return func() {
		once.Do(func() {
			g.mu.Lock()
			g.hold = false
			close(g.release)
			g.release = make(chan struct{})
			g.mu.Unlock()
		})
	}
}
