// SPDX-License-Identifier: Apache-2.0
//go:build linux

package engine

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/tonylturner/containd/pkg/dp/rules"
)

// These kernel tests route the first-command lab's client namespace to TCP
// echo servers through the engine's nft ruleset. The engine is never
// started, so its schedule planner never runs: every window opens and
// closes, and every horizon runs out, in the kernel alone. Run them as the
// first-command oracle documents, with -test.run 'KernelIdentity|KernelSchedule'.

const ksWait = 1500 * time.Millisecond // several retransmission timeouts

// echoServer echoes every byte on its ports and counts, per connection,
// the bytes it received.
type echoServer struct {
	mu    sync.Mutex
	conns map[string]net.Conn // client address:port -> server side
	bytes map[string]int
}

func startEchoServer(t *testing.T, ports ...int) *echoServer {
	t.Helper()
	s := &echoServer{conns: map[string]net.Conn{}, bytes: map[string]int{}}
	var wg sync.WaitGroup
	var listeners []net.Listener
	for _, port := range ports {
		var ln net.Listener
		if err := inNetns(fcServerNS, func() (err error) {
			ln, err = net.Listen("tcp", net.JoinHostPort(fcServerIP, strconv.Itoa(port)))
			return err
		}); err != nil {
			t.Fatal(err)
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				c, err := ln.Accept()
				if err != nil {
					return
				}
				s.mu.Lock()
				s.conns[c.RemoteAddr().String()] = c
				s.mu.Unlock()
				go s.echo(c)
			}
		}()
		listeners = append(listeners, ln)
	}
	t.Cleanup(func() {
		for _, ln := range listeners {
			_ = ln.Close()
		}
		s.mu.Lock()
		for _, c := range s.conns {
			_ = c.Close()
		}
		s.mu.Unlock()
		wg.Wait()
	})
	return s
}

func (s *echoServer) echo(c net.Conn) {
	key := c.RemoteAddr().String()
	buf := make([]byte, 512)
	for {
		n, err := c.Read(buf)
		s.mu.Lock()
		s.bytes[key] += n
		s.mu.Unlock()
		if n > 0 {
			if _, werr := c.Write(buf[:n]); werr != nil {
				return
			}
		}
		if err != nil {
			return
		}
	}
}

func (s *echoServer) received(client net.Conn) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.bytes[client.LocalAddr().String()]
}

// push sends from the server side of client's connection.
func (s *echoServer) push(t *testing.T, client net.Conn) {
	t.Helper()
	s.mu.Lock()
	c := s.conns[client.LocalAddr().String()]
	s.mu.Unlock()
	if c == nil {
		t.Fatalf("server has no connection from %s", client.LocalAddr())
	}
	if _, err := c.Write([]byte("push")); err != nil {
		t.Fatal(err)
	}
}

// ksLab is the lab with the engine's enforcement applied, never started.
type ksLab struct {
	t      *testing.T
	ctx    context.Context
	engine *Engine
	srv    *echoServer
	addrs  map[string]bool
}

func newKSLab(t *testing.T, horizon time.Duration, ports ...int) *ksLab {
	t.Helper()
	ctx := newFirstCommandLab(t)
	e, err := New(Config{Enforce: EnforceConfig{Enabled: true, TableName: "containd"}})
	if err != nil {
		t.Fatal(err)
	}
	e.compiler.ScheduleHorizon = horizon
	t.Cleanup(func() {
		fresh, err := New(Config{Events: e.Events()})
		if err == nil {
			err = e.Reconfigure(fresh) // deletes the tables
		}
		if err != nil {
			t.Errorf("remove enforcement: %v", err)
		}
	})
	return &ksLab{t: t, ctx: ctx, engine: e, srv: startEchoServer(t, ports...), addrs: map[string]bool{}}
}

func (l *ksLab) apply(snap rules.Snapshot) {
	l.t.Helper()
	if err := l.engine.ApplyRules(l.ctx, snap); err != nil {
		l.t.Fatalf("apply rules: %v", err)
	}
}

// dial connects from src to the server's port.
func (l *ksLab) dial(src string, port int) (net.Conn, error) {
	l.t.Helper()
	if !l.addrs[src] {
		fcRun(l.ctx, l.t, "ip", "-n", fcClientNS, "addr", "add", src+"/24", "dev", "fcp0")
		l.addrs[src] = true
	}
	var c net.Conn
	err := inNetns(fcClientNS, func() (err error) {
		d := net.Dialer{LocalAddr: &net.TCPAddr{IP: net.ParseIP(src)}, Timeout: fcReplyWait}
		c, err = d.DialContext(l.ctx, "tcp", net.JoinHostPort(fcServerIP, strconv.Itoa(port)))
		return err
	})
	if err == nil {
		l.t.Cleanup(func() { _ = c.Close() })
	}
	return c, err
}

// connect requires a connection and one echo on it.
func (l *ksLab) connect(src string, port int) net.Conn {
	l.t.Helper()
	c, err := l.dial(src, port)
	if err != nil {
		l.t.Fatalf("%s -> %d refused: %v", src, port, err)
	}
	l.echoes(c)
	return c
}

func (l *ksLab) refused(src string, port int) {
	l.t.Helper()
	if c, err := l.dial(src, port); err == nil {
		l.t.Fatalf("%s -> %d admitted (%s)", src, port, c.LocalAddr())
	}
}

// echoes requires a round trip on c.
func (l *ksLab) echoes(c net.Conn) {
	l.t.Helper()
	if _, err := c.Write([]byte("ping")); err != nil {
		l.t.Fatal(err)
	}
	_ = c.SetReadDeadline(time.Now().Add(fcReplyWait))
	buf := make([]byte, 4)
	if _, err := io.ReadFull(c, buf); err != nil || string(buf) != "ping" {
		l.t.Fatalf("no echo on %s: %q, %v", c.LocalAddr(), buf, err)
	}
}

// stopped requires that c carries nothing either way: the server receives
// none of the client's data and the client none of the server's.
func (l *ksLab) stopped(c net.Conn) {
	l.t.Helper()
	before := l.srv.received(c)
	if _, err := c.Write([]byte("data")); err != nil {
		l.t.Fatal(err)
	}
	l.srv.push(l.t, c)
	_ = c.SetReadDeadline(time.Now().Add(ksWait))
	buf := make([]byte, 16)
	n, err := c.Read(buf)
	var ne net.Error
	if n > 0 || !errors.As(err, &ne) || !ne.Timeout() {
		l.t.Fatalf("revoked connection %s still carries traffic: %q, %v", c.LocalAddr(), buf[:n], err)
	}
	if got := l.srv.received(c); got != before {
		l.t.Fatalf("server received %d bytes on revoked connection %s", got-before, c.LocalAddr())
	}
}

func tcpPorts(lo, hi int) []rules.Protocol {
	return []rules.Protocol{{Name: "tcp", Port: fmt.Sprintf("%d-%d", lo, hi)}}
}

// TestKernelIdentityBindings: only a bound opener with a listed label is
// admitted, a RESET with identities rejects only its bound openers, and
// removing a binding stops its established connection in both directions,
// except one that an unconditional ALLOW also admits.
func TestKernelIdentityBindings(t *testing.T) {
	l := newKSLab(t, 0, 7000, 7001, 7006)
	ops, guest, unbound := "198.18.50.11", "198.18.50.12", "198.18.50.13"
	snap := rules.Snapshot{
		Default: rules.ActionDeny,
		IdentityBindings: []rules.IdentityBinding{
			{IP: ops, Identities: []string{"operator"}},
			{IP: guest, Identities: []string{"guest"}},
		},
		Firewall: []rules.Entry{
			{ID: "operators", Identities: []string{"operator"}, Protocols: tcpPorts(7000, 7001), Action: rules.ActionAllow},
			{ID: "open-7001", Protocols: []rules.Protocol{{Name: "tcp", Port: "7001"}}, Action: rules.ActionAllow},
			{ID: "reset-guests", Identities: []string{"guest"}, Protocols: []rules.Protocol{{Name: "tcp", Port: "7006"}}, Action: rules.ActionReset},
		},
	}
	l.apply(snap)
	onlyIdentity := l.connect(ops, 7000)
	alsoOpen := l.connect(ops, 7001)
	l.refused(unbound, 7000)
	l.refused(guest, 7000)
	// The guest's SYN is reset at once; the unbound opener's is dropped by
	// the default and times out.
	if _, err := l.dial(guest, 7006); !errors.Is(err, syscall.ECONNREFUSED) {
		t.Fatalf("guest -> 7006: %v, want a reset", err)
	}
	if _, err := l.dial(unbound, 7006); err == nil || errors.Is(err, syscall.ECONNREFUSED) {
		t.Fatalf("unbound -> 7006: %v, want a silent drop", err)
	}

	snap.IdentityBindings = snap.IdentityBindings[1:]
	l.apply(snap)
	l.stopped(onlyIdentity)
	l.echoes(alsoOpen)
	l.srv.push(t, alsoOpen)
	buf := make([]byte, 4)
	_ = alsoOpen.SetReadDeadline(time.Now().Add(fcReplyWait))
	if _, err := io.ReadFull(alsoOpen, buf); err != nil || string(buf) != "push" {
		t.Fatalf("server data on the unconditionally admitted connection: %q, %v", buf, err)
	}
	l.refused(ops, 7000)
}

// TestKernelScheduleWindowOpensAndCloses applies a one-minute window in the
// near future and never refills it: the kernel opens the window for a
// scheduled ALLOW and applies a scheduled DENY to an established
// connection when it opens, then closes the ALLOW's established connection
// when it ends.
func TestKernelScheduleWindowOpensAndCloses(t *testing.T) {
	l := newKSLab(t, 0, 7002, 7003)
	now := time.Now().UTC()
	start := now.Truncate(time.Minute).Add(time.Minute)
	if start.Sub(now) < 10*time.Second {
		start = start.Add(time.Minute)
	}
	end := start.Add(time.Minute)
	window := rules.SchedulePredicate{DaysOfWeek: []string{start.Weekday().String()},
		StartTime: start.Format("15:04"), EndTime: end.Format("15:04")}
	src := "198.18.50.21"
	l.apply(rules.Snapshot{
		Default: rules.ActionAllow,
		Firewall: []rules.Entry{
			{ID: "closed-7002", Protocols: []rules.Protocol{{Name: "tcp", Port: "7002"}}, Action: rules.ActionDeny},
			{ID: "window-7002", Protocols: []rules.Protocol{{Name: "tcp", Port: "7002"}}, Action: rules.ActionAllow, Schedule: window},
			{ID: "window-deny-7003", Protocols: []rules.Protocol{{Name: "tcp", Port: "7003"}}, Action: rules.ActionDeny, Schedule: window},
		},
	})
	l.refused(src, 7002)
	beforeWindow := l.connect(src, 7003)

	time.Sleep(time.Until(start.Add(time.Second)))
	inWindow := l.connect(src, 7002)
	l.stopped(beforeWindow)
	l.refused(src, 7003)

	time.Sleep(time.Until(end.Add(time.Second)))
	l.stopped(inWindow)
	l.refused(src, 7002)
	l.connect(src, 7003)
}

// TestKernelScheduleHorizonExhausted plans a four-second horizon and never
// refills it: once it runs out, a scheduled ALLOW stops matching, for new
// and established connections, and a scheduled DENY applies.
func TestKernelScheduleHorizonExhausted(t *testing.T) {
	l := newKSLab(t, 4*time.Second, 7004, 7005)
	everyDay := rules.SchedulePredicate{DaysOfWeek: []string{"Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday", "Sunday"}}
	notToday := rules.SchedulePredicate{DaysOfWeek: []string{time.Now().UTC().AddDate(0, 0, 3).Weekday().String()}}
	src := "198.18.50.31"
	applied := time.Now()
	l.apply(rules.Snapshot{
		Default: rules.ActionAllow,
		Firewall: []rules.Entry{
			{ID: "closed-7004", Protocols: []rules.Protocol{{Name: "tcp", Port: "7004"}}, Action: rules.ActionDeny},
			{ID: "always-7004", Protocols: []rules.Protocol{{Name: "tcp", Port: "7004"}}, Action: rules.ActionAllow, Schedule: everyDay},
			{ID: "later-deny-7005", Protocols: []rules.Protocol{{Name: "tcp", Port: "7005"}}, Action: rules.ActionDeny, Schedule: notToday},
		},
	})
	allowed := l.connect(src, 7004)
	notDenied := l.connect(src, 7005)

	time.Sleep(time.Until(applied.Add(6 * time.Second)))
	l.stopped(allowed)
	l.stopped(notDenied)
	l.refused(src, 7004)
	l.refused(src, 7005)
}
