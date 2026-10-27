// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 containd Authors

//go:build linux

package engineapp

import (
	"bufio"
	"context"
	"fmt"
	"net/netip"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"testing"
	"time"

	"go.uber.org/zap"

	"github.com/tonylturner/containd/pkg/cp/config"
	"github.com/tonylturner/containd/pkg/dp/enforce"
	"github.com/tonylturner/containd/pkg/dp/engine"
	"github.com/tonylturner/containd/pkg/dp/events"
	"github.com/tonylturner/containd/pkg/dp/netcfg"
)

// TestGateManagerKernel runs the gate manager against the kernel: a client
// namespace reaches an HTTP server in another namespace through this one,
// which stands in for containd. Hand-written steering rules carrying the
// gate's marks deliver the client's SYN to the manager's transparent
// listeners; the manager dials the server with the client's address, so
// the server sees the client's IP on a port that is not the client's, and
// CloseMatching resets both legs. A masquerading variant proves the
// masquerade mark of the upstream socket. It runs only when
// CONTAIND_NETNS_KERNEL_TEST=1 inside a disposable Linux container with
// NET_ADMIN, NET_RAW and SYS_ADMIN, nft, iproute2 and Python; the container
// of scripts/gate-spike/run.sh has them:
//
//	docker run --rm --cap-add NET_ADMIN --cap-add NET_RAW --cap-add SYS_ADMIN \
//	  --sysctl net.ipv4.ip_forward=1 --sysctl net.ipv6.conf.all.forwarding=1 \
//	  --sysctl net.ipv4.conf.all.rp_filter=1 --sysctl net.ipv4.conf.default.rp_filter=1 \
//	  -e CONTAIND_NETNS_KERNEL_TEST=1 -e GOFLAGS=-mod=mod -v "$PWD:/src" -w /src \
//	  containd-gate-spike:<go version> go test -count=1 -run '^TestGateManagerKernel$' -v ./pkg/app/engine
func TestGateManagerKernel(t *testing.T) {
	lab := newGateLab(t)
	store := events.NewStore(256)
	admit := newGateTestAdmitter()
	scanner := &gateTestScanner{}
	scanner.ready.Store(true)
	g := newGateManager(zap.NewNop().Sugar(), scanner, admit, store, enforce.DefaultGatePlainPort, enforce.DefaultGateMasqPort)
	g.applyAV(config.AVConfig{Enabled: true, HTTPDownload: true})
	started := time.Now()
	g.setEnforcing(true)
	t.Cleanup(g.close)
	admit.await(t, enforce.GateAdmitOpen)
	t.Logf("gate open after %s", time.Since(started).Round(time.Millisecond))
	if st := g.status(); st.State != "open" || st.Warning != "" || st.RoutingError != "" {
		t.Fatalf("gate status %+v", st)
	}
	lab.serve(t, gateLabServerV4, 80)
	lab.serve(t, gateLabServerV6, 80)

	for _, tc := range []struct {
		name, server, client, wantPeer string
		masq                           bool
	}{
		{"ipv4 transparent", gateLabServerV4, gateLabClientV4, gateLabClientV4, false},
		{"ipv6 transparent", gateLabServerV6, gateLabClientV6, gateLabClientV6, false},
		{"ipv4 masqueraded", gateLabServerV4, gateLabClientV4, gateLabRouterV4, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			lab.install(t, tc.masq)
			before := countGateEvents(store, gateEventScanned)
			c := lab.get(t, tc.server, "/object")
			if c.err != "" {
				t.Fatalf("client: %s", c.err)
			}
			peer, port := parseGateLabReply(t, c.reply(t))
			if peer != tc.wantPeer {
				t.Fatalf("server saw %s, want %s", peer, tc.wantPeer)
			}
			if port == c.port {
				t.Fatalf("upstream leg used the client's port %s", port)
			}
			ev := awaitGateEvent(t, store, gateEventScanned, before)
			server := netip.AddrPortFrom(netip.MustParseAddr(tc.server), 80).String()
			if ev.Attributes["server"] != server || ev.Attributes["original_destination"] != server || ev.SrcIP != tc.client {
				t.Fatalf("event %+v", ev)
			}
			if ev.Attributes["verdict"] != "clean" {
				t.Fatalf("verdict %v", ev.Attributes["verdict"])
			}
		})
	}
	t.Run("close matching resets both legs", func(t *testing.T) {
		lab.install(t, false)
		c := lab.get(t, gateLabServerV4, "/hold")
		if c.err != "" {
			t.Fatalf("client: %s", c.err)
		}
		client := netip.MustParseAddrPort(net4(gateLabClientV4, c.port))
		deadline := time.Now().Add(5 * time.Second)
		for {
			if e := g.registry.lookup(client); e != nil && len(e.legs()) == 2 {
				break
			}
			if time.Now().After(deadline) {
				t.Fatalf("connection from %s not registered with its upstream leg", client)
			}
			time.Sleep(20 * time.Millisecond)
		}
		if n := g.CloseMatching(engine.GateCloseRequest{Src: client.Addr(), Dst: netip.MustParseAddr(gateLabServerV4), SrcPort: client.Port(), DstPort: 80}); n != 1 {
			t.Fatalf("closed %d connections, want 1", n)
		}
		if got := c.line(t); got != "error 104" {
			t.Fatalf("client saw %q, want a reset", got)
		}
		deadline = time.Now().Add(5 * time.Second)
		for {
			out := lab.run(t, "ss", "-Htn", "state", "established", "( dport = :80 )")
			if strings.TrimSpace(out) == "" {
				break
			}
			if time.Now().After(deadline) {
				t.Fatalf("upstream leg still established:\n%s", out)
			}
			time.Sleep(20 * time.Millisecond)
		}
		if n := g.registry.count(); n != 0 {
			t.Fatalf("%d connections registered after the reset", n)
		}
	})
}

const (
	gateLabClientV4 = "198.18.80.2"
	gateLabClientV6 = "fd18:80::2"
	gateLabServerV4 = "198.18.81.2"
	gateLabServerV6 = "fd18:81::2"
	gateLabRouterV4 = "198.18.81.1"
)

// gateLab is a client namespace behind gk0 and a server namespace behind
// gk1, with this namespace routing between them.
type gateLab struct {
	ctx            context.Context
	client, server string
	installed      bool
}

func newGateLab(t *testing.T) *gateLab {
	t.Helper()
	if os.Getenv("CONTAIND_NETNS_KERNEL_TEST") != "1" || os.Geteuid() != 0 {
		t.Skip("requires CONTAIND_NETNS_KERNEL_TEST=1 as root in a disposable Linux container with NET_ADMIN, NET_RAW and SYS_ADMIN")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	t.Cleanup(cancel)
	lab := &gateLab{ctx: ctx, client: "gkclient", server: "gkserver"}
	for _, s := range []string{"net/ipv4/ip_forward", "net/ipv6/conf/all/forwarding"} {
		if data, err := os.ReadFile("/proc/sys/" + s); err != nil || strings.TrimSpace(string(data)) != "1" {
			t.Fatalf("%s must be 1 (set it with docker run --sysctl): %q %v", s, data, err)
		}
	}
	type leaf struct{ ns, dev, peer, host4, host6, addr4, addr6, gw4, gw6 string }
	for _, l := range []leaf{
		{lab.client, "gk0", "gkp0", "198.18.80.1/24", "fd18:80::1/64", gateLabClientV4 + "/24", gateLabClientV6 + "/64", "198.18.80.1", "fd18:80::1"},
		{lab.server, "gk1", "gkp1", gateLabRouterV4 + "/24", "fd18:81::1/64", gateLabServerV4 + "/24", gateLabServerV6 + "/64", gateLabRouterV4, "fd18:81::1"},
	} {
		lab.run(t, "ip", "netns", "add", l.ns)
		t.Cleanup(func() { lab.run(t, "ip", "netns", "del", l.ns) })
		lab.run(t, "ip", "link", "add", l.dev, "type", "veth", "peer", "name", l.peer)
		t.Cleanup(func() { lab.run(t, "ip", "link", "del", l.dev) })
		lab.run(t, "ip", "link", "set", l.peer, "netns", l.ns)
		lab.run(t, "ip", "addr", "add", l.host4, "dev", l.dev)
		lab.run(t, "ip", "-6", "addr", "add", l.host6, "dev", l.dev, "nodad")
		lab.run(t, "ip", "link", "set", l.dev, "up")
		lab.run(t, "ip", "-n", l.ns, "addr", "add", l.addr4, "dev", l.peer)
		lab.run(t, "ip", "-n", l.ns, "-6", "addr", "add", l.addr6, "dev", l.peer, "nodad")
		lab.run(t, "ip", "-n", l.ns, "link", "set", l.peer, "up")
		lab.run(t, "ip", "-n", l.ns, "link", "set", "lo", "up")
		lab.run(t, "ip", "-n", l.ns, "route", "add", "default", "via", l.gw4)
		lab.run(t, "ip", "-n", l.ns, "-6", "route", "add", "default", "via", l.gw6)
	}
	t.Cleanup(func() {
		if err := netcfg.RemoveGateRouting(context.Background()); err != nil {
			t.Errorf("remove gate routing: %v", err)
		}
	})
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

// ruleset steers the client's HTTP to the gate with the gate's marks: the
// delivery and classification lines of the policy's prerouting chain, the
// upstream mark copy on output, the forward guard and, for masq, the
// masquerade keyed on the upstream socket's marks.
func gateLabRuleset(masq bool) string {
	hex := func(n uint32) string { return fmt.Sprintf("0x%08x", n) }
	port, sel, srcnat := enforce.DefaultGatePlainPort, "", ""
	if masq {
		port = enforce.DefaultGateMasqPort
		sel = " | " + hex(enforce.GateMasqSelCtMark)
		srcnat = "meta mark & " + hex(enforce.GateUpstreamSockMark|enforce.GateMasqSockMark) + " == " + hex(enforce.GateUpstreamSockMark|enforce.GateMasqSockMark) + " masquerade;"
	}
	// Longer names first: the replacer compares in argument order.
	r := strings.NewReplacer(
		"GATE_UP", hex(enforce.GateUpstreamSockMark), "GATE", hex(enforce.GateCtMark), "UP", hex(enforce.GateUpstreamCtMark),
		"LOCAL", hex(enforce.GateLocalPktMark), "PORT", strconv.Itoa(int(port)), "SEL", sel, "SRCNAT", srcnat,
	)
	return r.Replace(`table inet gate_lab {
  chain gate_pre {
    type filter hook prerouting priority -90; policy accept;
    iifname "lo" return;
    ct mark & UP == UP ct direction reply meta mark set meta mark | LOCAL accept;
    fib daddr type local return;
    meta l4proto tcp ct mark & GATE == GATE goto gate_deliver;
    ct state new tcp flags & (fin | syn | rst | ack) == syn iifname "gk0" tcp dport 80 ct mark set ct mark | GATESEL goto gate_deliver;
  }
  chain gate_deliver {
    meta nfproto ipv4 meta l4proto tcp tproxy ip to 127.0.0.1:PORT meta mark set meta mark | LOCAL accept;
    meta nfproto ipv6 meta l4proto tcp tproxy ip6 to [::1]:PORT meta mark set meta mark | LOCAL accept;
  }
  chain gate_out {
    type filter hook output priority -150; policy accept;
    meta mark & GATE_UP == GATE_UP ct mark set ct mark | UP;
  }
  chain forward {
    type filter hook forward priority filter; policy accept;
    ct mark & GATE == GATE drop;
  }
  chain srcnat {
    type nat hook postrouting priority srcnat; policy accept;
    SRCNAT
  }
}
`)
}

// install replaces the steering ruleset; the calling (sub)test's end removes it.
func (l *gateLab) install(t *testing.T, masq bool) {
	t.Helper()
	l.uninstall(t)
	cmd := exec.CommandContext(l.ctx, "nft", "-f", "-")
	cmd.Stdin = strings.NewReader(gateLabRuleset(masq))
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("nft: %v: %s\n%s", err, out, gateLabRuleset(masq))
	}
	l.installed = true
	t.Cleanup(func() { l.uninstall(t) })
}

func (l *gateLab) uninstall(t *testing.T) {
	t.Helper()
	if l.installed {
		l.installed = false
		l.run(t, "nft", "delete", "table", "inet", "gate_lab")
	}
}

const gateLabServerProgram = `import socket, sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
addr, port = sys.argv[1], int(sys.argv[2])
class Server(ThreadingHTTPServer):
    address_family = socket.AF_INET6 if ':' in addr else socket.AF_INET
class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == '/hold':
            try:
                self.rfile.read(1)
            except OSError:
                pass
            return
        body = ('peer=%s port=%d' % (self.client_address[0], self.client_address[1])).encode()
        self.send_response(200)
        self.send_header('Content-Length', str(len(body)))
        self.end_headers()
        self.wfile.write(body)
    def log_message(self, *args):
        pass
srv = Server((addr, port), Handler)
print('ready', flush=True)
srv.serve_forever()
`

// serve runs an HTTP server in the server namespace that answers GET with
// the peer address it saw and holds /hold open until the connection dies.
func (l *gateLab) serve(t *testing.T, addr string, port int) {
	t.Helper()
	server := exec.CommandContext(l.ctx, "ip", "netns", "exec", l.server, "python3", "-u", "-c", gateLabServerProgram, addr, strconv.Itoa(port))
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

const gateLabClientProgram = `import socket, sys
host, port, path = sys.argv[1], int(sys.argv[2]), sys.argv[3]
s = socket.socket(socket.AF_INET6 if ':' in host else socket.AF_INET)
s.settimeout(10)
try:
    s.connect((host, port))
except OSError as e:
    print('error', e.errno, flush=True); sys.exit(0)
print('connected', s.getsockname()[1], flush=True)
name = '[%s]' % host if ':' in host else host
data = b''
try:
    s.sendall(('GET %s HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n' % (path, name)).encode())
    while True:
        chunk = s.recv(65536)
        if not chunk:
            break
        data += chunk
except OSError as e:
    print('error', e.errno, flush=True); sys.exit(0)
body = data.split(b'\r\n\r\n', 1)[1] if b'\r\n\r\n' in data else b''
print('reply', body.decode(), flush=True)
`

// gateLabClient is one HTTP GET from the client namespace: it reports its
// local port once connected, then the body or the error that ended it.
type gateLabClient struct {
	out  *bufio.Scanner
	port string
	err  string
}

func (l *gateLab) get(t *testing.T, host, path string) *gateLabClient {
	t.Helper()
	cmd := exec.CommandContext(l.ctx, "ip", "netns", "exec", l.client, "python3", "-u", "-c", gateLabClientProgram, host, "80", path)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = cmd.Process.Kill(); _ = cmd.Wait() })
	c := &gateLabClient{out: bufio.NewScanner(stdout)}
	line := c.line(t)
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

func (c *gateLabClient) line(t *testing.T) string {
	t.Helper()
	if !c.out.Scan() {
		t.Fatal("client produced no further output")
	}
	return c.out.Text()
}

// reply returns the body the server answered; it fails on an error line.
func (c *gateLabClient) reply(t *testing.T) string {
	t.Helper()
	line := c.line(t)
	if !strings.HasPrefix(line, "reply ") {
		t.Fatalf("client: %q, want a reply", line)
	}
	return strings.TrimPrefix(line, "reply ")
}

// parseGateLabReply splits "peer=<ip> port=<n>".
func parseGateLabReply(t *testing.T, reply string) (peer, port string) {
	t.Helper()
	fields := strings.Fields(reply)
	if len(fields) != 2 || !strings.HasPrefix(fields[0], "peer=") || !strings.HasPrefix(fields[1], "port=") {
		t.Fatalf("server reply %q", reply)
	}
	return strings.TrimPrefix(fields[0], "peer="), strings.TrimPrefix(fields[1], "port=")
}

func countGateEvents(store *events.Store, kind string) int {
	n := 0
	for _, ev := range store.List(256) {
		if ev.Kind == kind {
			n++
		}
	}
	return n
}

// awaitGateEvent returns the newest event of kind once more than before
// have been recorded.
func awaitGateEvent(t *testing.T, store *events.Store, kind string, before int) events.Event {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		if countGateEvents(store, kind) > before {
			for _, ev := range store.List(256) {
				if ev.Kind == kind {
					return ev
				}
			}
		}
		if time.Now().After(deadline) {
			t.Fatalf("no new %s event recorded", kind)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

func net4(host, port string) string {
	return host + ":" + port
}
