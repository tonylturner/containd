// SPDX-License-Identifier: Apache-2.0
//go:build linux

package enforce

import (
	"errors"
	"io"
	"net"
	"runtime"
	"strconv"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"github.com/tonylturner/containd/pkg/dp/rules"
)

// The engine decides every client message of a queued ICS connection,
// identities and schedule included; the kernel must stop the rest of a
// connection that only a conditional ALLOW admitted once its predicate no
// longer holds: the replies and the server's own packets.
const (
	qrQueue  = 91
	qrServer = "198.18.160.2"
	qrPort   = 18120
	qrWait   = 1500 * time.Millisecond // several retransmission timeouts
)

// TestKernelQueuedConditionalRecheck queues conditional Modbus ALLOW and
// DENY scopes to a synthetic admitting-repeat consumer. Removing one
// opener's binding stops the
// server's data on that opener's established connection, while the opener
// still bound keeps its connection.
func TestKernelQueuedConditionalRecheck(t *testing.T) {
	for _, action := range []rules.Action{rules.ActionAllow, rules.ActionDeny} {
		t.Run(string(action), func(t *testing.T) { testKernelQueuedConditionalRecheck(t, action) })
	}
}

func testKernelQueuedConditionalRecheck(t *testing.T, action rules.Action) {
	lab := newNetnsLab(t, "qrc", 150, 90*time.Second)
	lab.run(t, "ip", "-n", lab.client, "route", "add", "198.18.160.0/24", "via", "198.18.150.1")
	lab.run(t, "ip", "-n", lab.target, "route", "add", "198.18.150.0/24", "via", "198.18.160.1")
	revoked, kept := "198.18.150.2", "198.18.150.3"
	lab.run(t, "ip", "-n", lab.client, "addr", "add", kept+"/24", "dev", "qrcp0")
	repeatPolicyQueue(t, lab.ctx, qrQueue, false)
	echoInNetns(t, lab.target, net.JoinHostPort(qrServer, strconv.Itoa(qrPort)))

	snap := &rules.Snapshot{
		Default: rules.ActionDeny,
		IdentityBindings: []rules.IdentityBinding{
			{IP: revoked, Identities: []string{"ops"}},
			{IP: kept, Identities: []string{"ops"}},
		},
		Firewall: []rules.Entry{{ID: "modbus-ops", Protocols: []rules.Protocol{{Name: "tcp", Port: strconv.Itoa(qrPort)}},
			ICS: rules.ICSPredicate{Mode: "enforce", Protocol: "modbus"}, Identities: []string{"ops"}, Action: action}},
	}
	c := NewCompiler()
	c.QueueID = qrQueue
	lab.apply(t, c, snap)
	a := dialFrom(t, lab.client, revoked)
	b := dialFrom(t, lab.client, kept)
	for _, conn := range []net.Conn{a, b} {
		if err := roundTrip(conn); err != nil {
			t.Fatalf("%s before the binding change: %v", conn.LocalAddr(), err)
		}
	}

	snap.IdentityBindings = snap.IdentityBindings[1:]
	lab.apply(t, c, snap)
	var ne net.Error
	if err := roundTrip(a); !errors.As(err, &ne) || !ne.Timeout() {
		t.Fatalf("server data reached %s after its binding was removed: %v", a.LocalAddr(), err)
	}
	if err := roundTrip(b); err != nil {
		t.Fatalf("connection of the opener still bound: %v", err)
	}
}

// echoInNetns runs a TCP echo server on addr in namespace ns until the test
// ends.
func echoInNetns(t *testing.T, ns, addr string) {
	t.Helper()
	var ln net.Listener
	if err := inNetns(ns, func() (err error) {
		ln, err = net.Listen("tcp", addr)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				_, _ = io.Copy(c, c)
			}()
		}
	}()
}

// dialFrom connects from src in namespace ns to the echo server.
func dialFrom(t *testing.T, ns, src string) net.Conn {
	t.Helper()
	var c net.Conn
	if err := inNetns(ns, func() (err error) {
		d := net.Dialer{LocalAddr: &net.TCPAddr{IP: net.ParseIP(src)}, Timeout: 2 * time.Second}
		c, err = d.Dial("tcp", net.JoinHostPort(qrServer, strconv.Itoa(qrPort)))
		return err
	}); err != nil {
		t.Fatalf("%s: %v", src, err)
	}
	t.Cleanup(func() { _ = c.Close() })
	return c
}

// roundTrip sends four bytes and waits for their echo.
func roundTrip(c net.Conn) error {
	if _, err := c.Write([]byte("ping")); err != nil {
		return err
	}
	_ = c.SetReadDeadline(time.Now().Add(qrWait))
	buf := make([]byte, 4)
	if _, err := io.ReadFull(c, buf); err != nil {
		return err
	}
	if string(buf) != "ping" {
		return errors.New("wrong echo " + strconv.Quote(string(buf)))
	}
	return nil
}

// inNetns runs fn on a thread in namespace ns. Sockets opened by fn stay in
// ns.
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
		// A thread that cannot return home stays locked and exits with
		// its goroutine.
		if unix.Setns(home, unix.CLONE_NEWNET) == nil {
			runtime.UnlockOSThread()
		}
		errc <- err
	}()
	return <-errc
}
