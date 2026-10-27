// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 containd Authors

//go:build linux

package engine

import (
	"context"
	"errors"
	"net"
	"slices"
	"strconv"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// fcReconnectBound bounds a reconnect from the port of a connection the
// engine or the client dropped: the client's first SYN retransmission
// comes one second after its SYN.
const fcReconnectBound = 3 * time.Second

// TestReconnectKernelSamePortAfterSilentLoss runs in the first-command
// kernel lab (see first_command_kernel_linux_test.go for how to run it). A
// client loses its connection without a FIN or RST, as when it restarts,
// and reconnects from the same source port. Connection tracking still
// holds the old connection established, so its SYN passes into it
// unanchored; the server's challenge ACK makes the client reset the old
// connection, and the client's next SYN starts the new one. The reconnect
// completes within fcReconnectBound and the new connection is inspected:
// its read is answered and its prohibited write never reaches the server.
func TestReconnectKernelSamePortAfterSilentLoss(t *testing.T) {
	ctx := newFirstCommandLab(t)
	srv := startModbusRecorder(t)
	startFirstCommandEngine(t, ctx)

	const src = "198.18.50.45"
	c := dialFirstCommand(ctx, t, src)
	c.read()
	port := c.localPort()
	c.vanish()
	next, took := dialFrom(ctx, t, src, port, 502)
	t.Logf("reconnect from %s:%d took %v", src, port, took)
	if took > fcReconnectBound {
		t.Fatalf("reconnect took %v, want at most %v", took, fcReconnectBound)
	}
	if ends := srv.ended(t, src, 1); !errors.Is(ends[0], syscall.ECONNRESET) {
		t.Fatalf("old server connection ended with %v, want the client's reset", ends[0])
	}
	next.read()
	next.write(next.next(6, 1, 0x1234))
	next.expectSilence()
	if fcs, _, regs := srv.seen(src); !slices.Equal(fcs, []uint8{3, 3}) || regs != [8]uint16{} {
		t.Fatalf("server received FCs %v, registers %v; want the two reads only", fcs, regs)
	}
}

// TestIECReconnectKernelSamePortAfterSilentLoss is
// TestReconnectKernelSamePortAfterSilentLoss for an IEC 104 envelope: the
// engine still tracks the lost connection's established session when the
// client's SYN arrives. The SYN passes into it and opens nothing; the
// client's RST at the station's challenge ACK closes the session; the
// client's next SYN opens the next one, within fcReconnectBound.
func TestIECReconnectKernelSamePortAfterSilentLoss(t *testing.T) {
	ctx := newFirstCommandLab(t)
	srv := startIECStation(t)
	startIECEngine(t, ctx)

	const src = "198.18.50.48"
	fcRun(ctx, t, "ip", "-n", fcClientNS, "addr", "add", src+"/24", "dev", "fcp0")
	c, _ := dialFrom(ctx, t, src, 0, iec104Port)
	c.startdt()
	port := c.localPort()
	c.vanish()
	next, took := dialFrom(ctx, t, src, port, iec104Port)
	t.Logf("reconnect from %s:%d took %v", src, port, took)
	if took > fcReconnectBound {
		t.Fatalf("reconnect took %v, want at most %v", took, fcReconnectBound)
	}
	if ends := srv.ended(t, src, 1); !errors.Is(ends[0], syscall.ECONNRESET) {
		t.Fatalf("old station connection ended with %v, want the client's reset", ends[0])
	}
	next.startdt()
}

// expectReset requires the connection to be reset within fcReplyWait
// without a reply.
func (c *fcClient) expectReset() {
	c.t.Helper()
	_ = c.conn.SetReadDeadline(time.Now().Add(fcReplyWait))
	b := make([]byte, 64)
	n, err := c.conn.Read(b)
	if n > 0 || !errors.Is(err, syscall.ECONNRESET) {
		c.t.Fatalf("connection from %s: read % x, %v; want a reset", c.src, b[:n], err)
	}
}

func (c *fcClient) localPort() int { return c.conn.LocalAddr().(*net.TCPAddr).Port }

// vanish drops the client's socket without sending anything: in TCP repair
// mode a close sends neither FIN nor RST.
func (c *fcClient) vanish() {
	c.t.Helper()
	raw, err := c.conn.SyscallConn()
	if err != nil {
		c.t.Fatal(err)
	}
	var serr error
	if err := raw.Control(func(fd uintptr) {
		serr = unix.SetsockoptInt(int(fd), unix.IPPROTO_TCP, unix.TCP_REPAIR, 1)
	}); err != nil || serr != nil {
		c.t.Fatalf("enter repair mode: %v, %v", err, serr)
	}
	_ = c.conn.Close()
}

// dialFrom connects from src:port to the server's dport and returns the
// client and how long the connect took.
func dialFrom(ctx context.Context, t *testing.T, src string, port, dport int) (*fcClient, time.Duration) {
	t.Helper()
	var conn net.Conn
	start := time.Now()
	err := inNetns(fcClientNS, func() (err error) {
		d := net.Dialer{LocalAddr: &net.TCPAddr{IP: net.ParseIP(src), Port: port}, Timeout: 2 * fcReconnectBound}
		conn, err = d.DialContext(ctx, "tcp", net.JoinHostPort(fcServerIP, strconv.Itoa(dport)))
		return err
	})
	took := time.Since(start)
	if err != nil {
		t.Fatalf("connect from %s:%d after %v: %v", src, port, took, err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	return &fcClient{t: t, src: src, conn: conn.(*net.TCPConn), tid: 50}, took
}
