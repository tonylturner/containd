// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 containd Authors

//go:build linux

package engine

import (
	"net"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// TestForgedSYNKernelRestartPickup runs in the first-command kernel lab
// (see first_command_kernel_linux_test.go for how to run it). After an
// engine restart under an open connection, a SYN is sent in that
// connection whose sequence number would anchor a new stream at the
// client's next byte, as an attacker who knows the sequence numbers could
// send to choose where framing starts. The kernel still tracks the
// connection, so the SYN does not start a new one: the connection's next
// read is a mid-stream pickup, never reaches the server and resets the
// connection, and a new connection from the same address is still
// inspected and answered.
func TestForgedSYNKernelRestartPickup(t *testing.T) {
	ctx := newFirstCommandLab(t)
	srv := startModbusRecorder(t)
	e := startFirstCommandEngine(t, ctx)

	const src = "198.18.50.44"
	c := dialFirstCommand(ctx, t, src)
	c.read()
	restartFirstCommandEngine(ctx, t, e, nil)

	c.forgeSYN(502)
	c.write(c.next(3, 0, 2))
	c.expectReset()
	if fcs, n, _ := srv.seen(src); len(fcs) != 1 || n != 12 {
		t.Fatalf("server received FCs %v in %d bytes, want only the read before the restart", fcs, n)
	}

	var conn net.Conn
	err := inNetns(fcClientNS, func() (err error) {
		d := net.Dialer{LocalAddr: &net.TCPAddr{IP: net.ParseIP(src)}, Timeout: fcReplyWait}
		conn, err = d.DialContext(ctx, "tcp", net.JoinHostPort(fcServerIP, "502"))
		return err
	})
	if err != nil {
		t.Fatalf("reconnect from %s: %v", src, err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	next := &fcClient{t: t, src: src, conn: conn.(*net.TCPConn), tid: 50}
	next.read()
	next.write(next.next(6, 1, 0x1234))
	next.expectReset()
	if fcs, _, regs := srv.seen(src); len(fcs) != 2 || regs != [8]uint16{} {
		t.Fatalf("server received FCs %v, registers %v; want the two reads only", fcs, regs)
	}
}

// TestForgedSYNKernelLiveConnection sends, after the head of a read, a SYN
// in the open connection whose sequence number would anchor a new stream
// at the client's next byte. It passes without anchoring: the crafted
// rest, which completes the read and a prohibited write were the stream
// anchored at it, is framed from the read's start and dropped with the
// write.
func TestForgedSYNKernelLiveConnection(t *testing.T) {
	ctx := newFirstCommandLab(t)
	srv := startModbusRecorder(t)
	startFirstCommandEngine(t, ctx)

	c := dialFirstCommand(ctx, t, "198.18.50.47")
	read := c.next(3, 0, 2)
	c.write(read[:8])
	c.forgeSYN(502)
	// Transaction ID 0x00FE: the misframed MBAP length field.
	c.write(append(read[8:], modbusADU(0x00FE, 6, 1, 0x1234)...))
	c.expectReset()
	if fcs, n, regs := srv.seen(c.src); len(fcs) != 0 || n != 8 || regs != [8]uint16{} {
		t.Fatalf("server received FCs %v in %d bytes, registers %v; want only the 8-byte read head", fcs, n, regs)
	}
}

// forgeSYN sends, from the client's address and port, a SYN to the server
// port whose sequence number precedes the client's next byte, and gives
// the server time to answer it.
func (c *fcClient) forgeSYN(dport uint16) {
	c.t.Helper()
	local := c.conn.LocalAddr().(*net.TCPAddr)
	syn := rawTCPSegment(local.IP, net.ParseIP(fcServerIP), uint16(local.Port), dport, c.sendSeq()-1, 0x02) // SYN
	if err := inNetns(fcClientNS, func() error { return sendRaw(syn, net.ParseIP(fcServerIP)) }); err != nil {
		c.t.Fatalf("send SYN: %v", err)
	}
	time.Sleep(100 * time.Millisecond)
}

// tcpSendQueue selects the send queue for TCP_QUEUE_SEQ (TCP_SEND_QUEUE).
const tcpSendQueue = 2

// sendSeq returns the sequence number of the next byte the client sends,
// read in TCP repair mode, which is left without a window probe.
func (c *fcClient) sendSeq() uint32 {
	c.t.Helper()
	raw, err := c.conn.SyscallConn()
	if err != nil {
		c.t.Fatal(err)
	}
	var seq int
	var serr error
	err = raw.Control(func(fd uintptr) {
		s := int(fd)
		if serr = unix.SetsockoptInt(s, unix.IPPROTO_TCP, unix.TCP_REPAIR, 1); serr != nil {
			return
		}
		defer func() {
			if err := unix.SetsockoptInt(s, unix.IPPROTO_TCP, unix.TCP_REPAIR, -1); err != nil && serr == nil {
				serr = err
			}
		}()
		if serr = unix.SetsockoptInt(s, unix.IPPROTO_TCP, unix.TCP_REPAIR_QUEUE, tcpSendQueue); serr != nil {
			return
		}
		seq, serr = unix.GetsockoptInt(s, unix.IPPROTO_TCP, unix.TCP_QUEUE_SEQ)
	})
	if err != nil || serr != nil {
		c.t.Fatalf("read the send sequence: %v, %v", err, serr)
	}
	return uint32(seq)
}
