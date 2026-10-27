// SPDX-License-Identifier: Apache-2.0
//go:build linux

package engine

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"runtime"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"github.com/tonylturner/containd/pkg/dp/rules"
)

// The kernel oracle routes a client namespace through this namespace's
// forward chain to a recording Modbus server namespace. containd's engine
// installs its nft ruleset here and decides the queued packets on NFQUEUE.
// It replaces containd's nft tables and enables forwarding in this
// namespace, so it runs only when CONTAIND_NETNS_KERNEL_TEST=1 inside a
// disposable privileged Linux container with nft and iproute2:
//
//	GOOS=linux CGO_ENABLED=0 go test -c -o build/engine.test ./pkg/dp/engine
//	docker run --rm --privileged -e CONTAIND_NETNS_KERNEL_TEST=1 -v "$PWD/build:/w" alpine:3.21 \
//	  sh -c 'apk add -q nftables iproute2 && /w/engine.test -test.run FirstCommandKernel -test.v'
const (
	fcClientNS   = "fcclient"
	fcServerNS   = "fcserver"
	fcServerIP   = "198.18.60.2"
	fcQueue      = 77
	fcQuietWait  = 1500 * time.Millisecond // several retransmission timeouts
	fcReplyWait  = 2 * time.Second
	fcLabTimeout = 3 * time.Minute
)

// fcRun runs a command in this namespace.
func fcRun(ctx context.Context, t *testing.T, args ...string) string {
	t.Helper()
	out, err := exec.CommandContext(ctx, args[0], args[1:]...).CombinedOutput()
	if err != nil {
		t.Fatalf("%v: %v: %s", args, err, out)
	}
	return string(out)
}

// newFirstCommandLab creates the client (198.18.50.0/24 behind fc0) and
// server (198.18.60.0/24 behind fc1) namespaces and enables forwarding.
func newFirstCommandLab(t *testing.T) context.Context {
	t.Helper()
	if os.Getenv("CONTAIND_NETNS_KERNEL_TEST") != "1" || os.Geteuid() != 0 {
		t.Skip("requires CONTAIND_NETNS_KERNEL_TEST=1 in a disposable privileged Linux container with nft and iproute2")
	}
	ctx, cancel := context.WithTimeout(context.Background(), fcLabTimeout)
	t.Cleanup(cancel) // registered first, so it runs after every other cleanup
	for i, ns := range []string{fcClientNS, fcServerNS} {
		dev, peer := fmt.Sprintf("fc%d", i), fmt.Sprintf("fcp%d", i)
		fcRun(ctx, t, "ip", "netns", "add", ns)
		t.Cleanup(func() { fcRun(ctx, t, "ip", "netns", "del", ns) })
		fcRun(ctx, t, "ip", "link", "add", dev, "type", "veth", "peer", "name", peer)
		t.Cleanup(func() { fcRun(ctx, t, "ip", "link", "del", dev) })
		fcRun(ctx, t, "ip", "link", "set", peer, "netns", ns)
		fcRun(ctx, t, "ip", "addr", "add", fmt.Sprintf("198.18.%d.1/24", 50+i*10), "dev", dev)
		fcRun(ctx, t, "ip", "link", "set", dev, "up")
		fcRun(ctx, t, "ip", "-n", ns, "addr", "add", fmt.Sprintf("198.18.%d.2/24", 50+i*10), "dev", peer)
		fcRun(ctx, t, "ip", "-n", ns, "link", "set", peer, "up")
		fcRun(ctx, t, "ip", "-n", ns, "link", "set", "lo", "up")
	}
	fcRun(ctx, t, "ip", "-n", fcClientNS, "route", "add", "default", "via", "198.18.50.1")
	fcRun(ctx, t, "ip", "-n", fcServerNS, "route", "add", "198.18.50.0/24", "via", "198.18.60.1")
	if err := os.WriteFile("/proc/sys/net/ipv4/ip_forward", []byte("1"), 0600); err != nil {
		t.Fatal(err)
	}
	return ctx
}

// inNetns runs fn on a thread switched into network namespace ns. Sockets
// fn creates stay in ns. If the thread cannot switch back it stays locked
// and exits with its goroutine.
func inNetns(ns string, fn func() error) error {
	errc := make(chan error, 1)
	go func() {
		runtime.LockOSThread()
		home, err := unix.Open("/proc/thread-self/ns/net", unix.O_RDONLY|unix.O_CLOEXEC, 0)
		if err != nil {
			runtime.UnlockOSThread()
			errc <- err
			return
		}
		defer unix.Close(home)
		target, err := unix.Open("/run/netns/"+ns, unix.O_RDONLY|unix.O_CLOEXEC, 0)
		if err != nil {
			runtime.UnlockOSThread()
			errc <- err
			return
		}
		defer unix.Close(target)
		if err := unix.Setns(target, unix.CLONE_NEWNET); err != nil {
			runtime.UnlockOSThread()
			errc <- err
			return
		}
		err = fn()
		if unix.Setns(home, unix.CLONE_NEWNET) == nil {
			runtime.UnlockOSThread()
		}
		errc <- err
	}()
	return <-errc
}

// modbusRecorder is a Modbus/TCP server holding eight registers. It
// records, per client address, the function code of every complete ADU
// before it acts on or answers the ADU.
type modbusRecorder struct {
	*kernelServer
	mu   sync.Mutex
	fcs  map[string][]uint8
	regs [8]uint16
}

func startModbusRecorder(t *testing.T) *modbusRecorder {
	t.Helper()
	r := &modbusRecorder{fcs: map[string][]uint8{}}
	r.kernelServer = startKernelServer(t, 502, r.answer)
	return r
}

// answer handles the ADU at the start of buf.
func (r *modbusRecorder) answer(src string, buf []byte) (int, []byte, error) {
	if len(buf) < 8 {
		return 0, nil, nil
	}
	total := 6 + int(binary.BigEndian.Uint16(buf[4:6]))
	switch {
	case total < 8:
		return 0, nil, errors.New("not Modbus/TCP: no PDU")
	case len(buf) < total:
		return 0, nil, nil
	}
	return total, r.handle(src, buf[:total]), nil
}

// handle records and executes one ADU and returns its response.
func (r *modbusRecorder) handle(src string, adu []byte) []byte {
	r.mu.Lock()
	defer r.mu.Unlock()
	fc := adu[7]
	r.fcs[src] = append(r.fcs[src], fc)
	pdu := []byte{fc ^ 0x80, 0x01} // illegal function
	switch {
	case fc == 3 && len(adu) == 12:
		addr, qty := int(binary.BigEndian.Uint16(adu[8:])), int(binary.BigEndian.Uint16(adu[10:]))
		if addr+qty <= len(r.regs) {
			pdu = []byte{3, byte(2 * qty)}
			for _, v := range r.regs[addr : addr+qty] {
				pdu = binary.BigEndian.AppendUint16(pdu, v)
			}
		}
	case fc == 6 && len(adu) == 12:
		if addr := int(binary.BigEndian.Uint16(adu[8:])); addr < len(r.regs) {
			r.regs[addr] = binary.BigEndian.Uint16(adu[10:])
			pdu = adu[7:]
		}
	case fc == 8:
		pdu = adu[7:]
	}
	out := append([]byte(nil), adu[:4]...)
	out = binary.BigEndian.AppendUint16(out, uint16(len(pdu)+1))
	return append(append(out, adu[6]), pdu...)
}

// seen returns what the server received from src and its registers.
func (r *modbusRecorder) seen(src string) (fcs []uint8, n int, regs [8]uint16) {
	n = r.received(src)
	r.mu.Lock()
	defer r.mu.Unlock()
	return slices.Clone(r.fcs[src]), n, r.regs
}

// startFirstCommandEngine runs the engine on NFQUEUE fcQueue with the
// Modbus enforce policy applied to this namespace's nft ruleset.
func startFirstCommandEngine(t *testing.T, ctx context.Context) *Engine {
	t.Helper()
	scope := func(id string, action rules.Action, ics rules.ICSPredicate) rules.Entry {
		return rules.Entry{
			ID: id, Sources: []string{"198.18.50.0/24"}, Destinations: []string{fcServerIP + "/32"},
			Protocols: []rules.Protocol{{Name: "tcp", Port: "502"}}, ICS: ics, Action: action,
		}
	}
	return startKernelEngine(t, ctx, rules.Snapshot{Default: rules.ActionDeny, Firewall: []rules.Entry{
		scope("modbus-read", rules.ActionAllow, rules.ICSPredicate{Protocol: "modbus", FunctionCode: []uint8{3}, ReadOnly: true}),
		scope("modbus-write-deny", rules.ActionDeny, rules.ICSPredicate{Protocol: "modbus", FunctionCode: []uint8{6}, WriteOnly: true}),
		scope("modbus-diag-deny", rules.ActionDeny, rules.ICSPredicate{Protocol: "modbus", FunctionCode: []uint8{8}}),
	}})
}

// startKernelEngine runs the engine on NFQUEUE fcQueue, with its reset
// injector, and applies snap to this namespace's nft ruleset.
func startKernelEngine(t *testing.T, ctx context.Context, snap rules.Snapshot) *Engine {
	t.Helper()
	var errMu sync.Mutex
	var errs []string
	e, err := New(Config{
		Enforce:      EnforceConfig{Enabled: true, TableName: "containd"},
		DPIEnabled:   true,
		DPIMode:      "enforce",
		NFQueueGroup: fcQueue,
		OnError: func(err error) {
			errMu.Lock()
			errs = append(errs, err.Error())
			errMu.Unlock()
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	runCtx, cancel := context.WithCancel(ctx)
	if err := e.Start(runCtx); err != nil {
		cancel()
		t.Fatalf("start engine on NFQUEUE %d: %v", fcQueue, err)
	}
	t.Cleanup(func() {
		fresh, err := New(Config{Events: e.Events()})
		if err == nil {
			err = e.Reconfigure(fresh) // stops the queue and deletes the tables
		}
		cancel()
		if err != nil {
			t.Errorf("stop engine: %v", err)
		}
		errMu.Lock()
		defer errMu.Unlock()
		for _, msg := range errs {
			t.Logf("engine error: %s", msg)
		}
	})
	if err := e.ApplyRules(ctx, snap); err != nil {
		t.Fatalf("apply rules: %v", err)
	}
	return e
}

// fcClient is one connection from its own client address.
type fcClient struct {
	t    *testing.T
	src  string
	conn *net.TCPConn
	tid  uint16
}

func dialFirstCommand(ctx context.Context, t *testing.T, src string) *fcClient {
	t.Helper()
	fcRun(ctx, t, "ip", "-n", fcClientNS, "addr", "add", src+"/24", "dev", "fcp0")
	var c net.Conn
	err := inNetns(fcClientNS, func() (err error) {
		d := net.Dialer{LocalAddr: &net.TCPAddr{IP: net.ParseIP(src)}, Timeout: fcReplyWait}
		c, err = d.DialContext(ctx, "tcp", net.JoinHostPort(fcServerIP, "502"))
		return err
	})
	if err != nil {
		t.Fatalf("connect from %s: %v", src, err)
	}
	t.Cleanup(func() { _ = c.Close() })
	return &fcClient{t: t, src: src, conn: c.(*net.TCPConn), tid: 1}
}

// write sends b in one segment (TCP_NODELAY is Go's default) and gives
// the stack time to put the next write in its own segment.
func (c *fcClient) write(b []byte) {
	c.t.Helper()
	if _, err := c.conn.Write(b); err != nil {
		c.t.Fatal(err)
	}
	time.Sleep(50 * time.Millisecond)
}

func (c *fcClient) next(fc byte, a, b uint16) []byte {
	c.tid++
	return modbusADU(c.tid, fc, a, b)
}

// read sends an allowed read of registers 0-1 and requires the answer.
func (c *fcClient) read() {
	c.t.Helper()
	c.write(c.next(3, 0, 2))
	c.expectReadReply()
}

func (c *fcClient) expectReadReply() {
	c.t.Helper()
	_ = c.conn.SetReadDeadline(time.Now().Add(fcReplyWait))
	reply := make([]byte, 13)
	if _, err := io.ReadFull(c.conn, reply); err != nil {
		c.t.Fatalf("allowed read from %s got no reply: %v", c.src, err)
	}
	if reply[7] != 3 || string(reply[9:]) != "\x00\x00\x00\x00" {
		c.t.Fatalf("read reply % x, want FC 3 with registers 0-1 still 0", reply)
	}
}

// expectSilence requires that no reply arrives while the client's stack
// retransmits the unanswered data at least once.
func (c *fcClient) expectSilence() {
	c.t.Helper()
	_ = c.conn.SetReadDeadline(time.Now().Add(fcQuietWait))
	b := make([]byte, 64)
	n, err := c.conn.Read(b)
	var ne net.Error
	if n > 0 || !errors.As(err, &ne) || !ne.Timeout() {
		c.t.Fatalf("server answered the prohibited command: % x, %v", b[:n], err)
	}
	raw, err := c.conn.SyscallConn()
	if err != nil {
		c.t.Fatal(err)
	}
	var info *unix.TCPInfo
	var ierr error
	if err := raw.Control(func(fd uintptr) {
		info, ierr = unix.GetsockoptTCPInfo(int(fd), unix.IPPROTO_TCP, unix.TCP_INFO)
	}); err != nil || ierr != nil {
		c.t.Fatal(err, ierr)
	}
	if info.Total_retrans == 0 {
		c.t.Fatal("the client never retransmitted the dropped segment")
	}
}

// TestFirstCommandKernelOracle sends each prohibited command from a fresh
// client address and checks the server: allowed reads reach it and are
// answered; the first prohibited command, and every retransmission of it,
// never completes there and no register changes.
func TestFirstCommandKernelOracle(t *testing.T) {
	ctx := newFirstCommandLab(t)
	srv := startModbusRecorder(t)
	startFirstCommandEngine(t, ctx)

	host := 10
	type step struct {
		fcs   []uint8 // complete ADUs the server must have from this client
		bytes int     // bytes the server must have from this client
	}
	run := func(name string, send func(c *fcClient) step) {
		t.Run(name, func(t *testing.T) {
			host++
			c := dialFirstCommand(ctx, t, fmt.Sprintf("198.18.50.%d", host))
			want := send(c)
			fcs, n, regs := srv.seen(c.src)
			if !slices.Equal(fcs, want.fcs) || n != want.bytes {
				t.Fatalf("server received FCs %v in %d bytes, want %v in %d", fcs, n, want.fcs, want.bytes)
			}
			if regs != [8]uint16{} {
				t.Fatalf("server registers changed: %v", regs)
			}
		})
	}
	write := func(c *fcClient) []byte { return c.next(6, 1, 0x1234) }
	diag := func(c *fcClient) []byte { return c.next(8, 0, 0xA537) }

	run("first payload fc6 write", func(c *fcClient) step {
		c.write(write(c))
		c.expectReset()
		return step{}
	})
	run("first payload fc8 diagnostics", func(c *fcClient) step {
		c.write(diag(c))
		c.expectReset()
		return step{}
	})
	run("fc6 write after reads", func(c *fcClient) step {
		c.read()
		c.read()
		c.write(write(c))
		c.expectReset()
		return step{fcs: []uint8{3, 3}, bytes: 24}
	})
	run("fc8 diagnostics after read", func(c *fcClient) step {
		c.read()
		c.write(diag(c))
		c.expectReset()
		return step{fcs: []uint8{3}, bytes: 12}
	})
	run("read and fc6 write coalesced", func(c *fcClient) step {
		c.write(append(c.next(3, 0, 2), write(c)...))
		c.expectReset()
		return step{}
	})
	run("read coalesced with fc6 write head", func(c *fcClient) step {
		w := write(c)
		c.write(append(c.next(3, 0, 2), w[:7]...))
		c.expectReadReply()
		c.write(w[7:])
		c.expectReset()
		return step{fcs: []uint8{3}, bytes: 19}
	})
	for k := 1; k < 12; k++ {
		run(fmt.Sprintf("fc6 write split at %d", k), func(c *fcClient) step {
			c.read()
			w := write(c)
			c.write(w[:k])
			c.write(w[k:])
			c.expectReset()
			return step{fcs: []uint8{3}, bytes: 12 + k}
		})
	}
	run("read on a fresh flow after every denial", func(c *fcClient) step {
		c.read()
		return step{fcs: []uint8{3}, bytes: 12}
	})

	// DPI must not install a service-wide block.
	out := fcRun(ctx, t, "nft", "list", "set", "inet", "containd", "block_flows")
	if strings.Contains(out, "198.18.50.11 . "+fcServerIP+" . tcp . 502") {
		t.Fatalf("DPI installed a block:\n%s", out)
	}
}
