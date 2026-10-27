// SPDX-License-Identifier: Apache-2.0
//go:build linux

package engine

import (
	"context"
	"encoding/binary"
	"errors"
	"math/rand/v2"
	"net"
	"slices"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"github.com/tonylturner/containd/pkg/dp/enforce"
	"github.com/tonylturner/containd/pkg/dp/session"
)

// TestStreamResyncKernelOutOfWindowRST runs in the first-command kernel
// lab (see first_command_kernel_linux_test.go for how to run it). After the
// head of a read, a RST at a random sequence number is sent on the
// client's connection; the server's stack ignores it. The crafted rest
// would complete the read and a prohibited write were the engine's stream
// restarted at it, so the server must receive neither.
func TestStreamResyncKernelOutOfWindowRST(t *testing.T) {
	ctx := newFirstCommandLab(t)
	srv := startModbusRecorder(t)
	startFirstCommandEngine(t, ctx)

	c := dialFirstCommand(ctx, t, "198.18.50.40")
	read := c.next(3, 0, 2)
	c.write(read[:8])
	local := c.conn.LocalAddr().(*net.TCPAddr)
	// One sequence number in 2^32 is the server's next one.
	rst := rawTCPSegment(local.IP, net.ParseIP(fcServerIP), uint16(local.Port), 502, rand.Uint32(), 0x04) // RST
	if err := inNetns(fcClientNS, func() error { return sendRaw(rst, net.ParseIP(fcServerIP)) }); err != nil {
		t.Fatalf("send RST: %v", err)
	}
	// Transaction ID 0x00FE: the misframed MBAP length field.
	c.write(append(read[8:], modbusADU(0x00FE, 6, 1, 0x1234)...))
	c.expectReset()
	fcs, n, regs := srv.seen(c.src)
	if len(fcs) != 0 || n != 8 || regs != [8]uint16{} {
		t.Fatalf("server received FCs %v in %d bytes, registers %v; want only the 8-byte read head", fcs, n, regs)
	}
}

// TestStreamResyncKernelRestartPickup restarts the engine under an open
// connection. The connection's next read is a mid-stream pickup: it never
// reaches the server, and the engine resets the connection at both
// endpoints at once. The client then reconnects from the same source port
// and its read is answered.
func TestStreamResyncKernelRestartPickup(t *testing.T) {
	ctx := newFirstCommandLab(t)
	srv := startModbusRecorder(t)
	e := startFirstCommandEngine(t, ctx)

	const src = "198.18.50.41"
	c := dialFirstCommand(ctx, t, src)
	c.read()
	restartFirstCommandEngine(ctx, t, e, nil)

	start := time.Now()
	c.write(c.next(3, 0, 2))
	c.expectReset()
	t.Logf("picked-up connection reset after %v", time.Since(start))
	if ends := srv.ended(t, src, 1); !errors.Is(ends[0], syscall.ECONNRESET) {
		t.Fatalf("server connection ended with %v, want a reset", ends[0])
	}
	port := c.localPort()
	_ = c.conn.Close()
	next, took := dialFrom(ctx, t, src, port, 502)
	t.Logf("reconnect from %s:%d took %v", src, port, took)
	next.read()
	if fcs, _, _ := srv.seen(src); !slices.Equal(fcs, []uint8{3, 3}) {
		t.Fatalf("server answered FCs %v, want the read before the restart and the new connection's read", fcs)
	}
}

// restartFirstCommandEngine replaces the running engine with a fresh one
// under the same rules, as an engine restart does. A non-nil updater
// replaces the nft dynamic-block updater.
func restartFirstCommandEngine(ctx context.Context, t *testing.T, e *Engine, updater enforce.Updater) {
	t.Helper()
	snap := e.CurrentRules()
	fresh, err := New(Config{
		Enforce:      EnforceConfig{Enabled: true, TableName: "containd", Updater: updater},
		DPIEnabled:   true,
		DPIMode:      "enforce",
		NFQueueGroup: fcQueue,
		Events:       e.Events(),
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := e.Reconfigure(fresh); err != nil {
		t.Fatalf("restart engine: %v", err)
	}
	if err := e.Start(ctx); err != nil {
		t.Fatalf("start engine again: %v", err)
	}
	if err := e.ApplyRules(ctx, *snap); err != nil {
		t.Fatalf("apply rules again: %v", err)
	}
}

// failingUpdater refuses every dynamic block.
type failingUpdater struct{}

func (failingUpdater) BlockHostTemp(context.Context, net.IP, time.Duration) error {
	return errors.New("nft: permission denied")
}

func (failingUpdater) BlockFlowTemp(context.Context, net.IP, net.IP, string, string, time.Duration) error {
	return errors.New("nft: permission denied")
}

// TestStreamResyncKernelDeniedRetransmission denies a write while
// reset injection fails. The client's stack keeps retransmitting the write;
// the retransmissions after the 30 s userspace cached denial expired must
// not reach the server either. Another client's reads, 5 s before and 27 s
// after the write, run the reassembly idle sweep while the denied stream is
// still recent, so that stream keeps the consumed history the
// retransmission matches. It runs for about a minute.
func TestStreamResyncKernelDeniedRetransmission(t *testing.T) {
	ctx := newFirstCommandLab(t)
	srv := startModbusRecorder(t)
	e := startFirstCommandEngine(t, ctx)
	restartFirstCommandEngine(ctx, t, e, failingUpdater{})
	inj := &session.Fake{}
	inj.SetError(errors.New("reset send failure"))
	if err := e.iec.injector.Close(); err != nil {
		t.Fatal(err)
	}
	e.iec.injector = inj

	c := dialFirstCommand(ctx, t, "198.18.50.42")
	other := dialFirstCommand(ctx, t, "198.18.50.43")
	other.read() // the first idle sweep
	time.Sleep(5 * time.Second)
	c.read()
	c.write(c.next(6, 1, 0x1234))
	sent := time.Now()
	c.expectSilence()
	if got := len(inj.Resets()); got != 2 {
		t.Fatalf("reset attempts %d, want both peers", got)
	}
	raw, err := c.conn.SyscallConn()
	if err != nil {
		t.Fatal(err)
	}
	swept := false
	for {
		if !swept && time.Since(sent) > 27*time.Second {
			other.read()
			swept = true
		}
		var info *unix.TCPInfo
		var ierr error
		if err := raw.Control(func(fd uintptr) {
			info, ierr = unix.GetsockoptTCPInfo(int(fd), unix.IPPROTO_TCP, unix.TCP_INFO)
		}); err != nil || ierr != nil {
			t.Fatal(err, ierr)
		}
		// The first retransmission after 30 s plus a margin.
		if time.Since(sent) > 35*time.Second && info.Total_retrans > 0 && time.Duration(info.Last_data_sent)*time.Millisecond < time.Since(sent)-30*time.Second {
			break
		}
		if time.Since(sent) > 2*time.Minute {
			t.Fatalf("no retransmission after the cached denial expired (%d retransmissions)", info.Total_retrans)
		}
		time.Sleep(time.Second)
	}
	time.Sleep(fcReplyWait) // the retransmission reaches the server at once, if at all
	if fcs, _, regs := srv.seen(c.src); !slices.Equal(fcs, []uint8{3}) || regs != [8]uint16{} {
		t.Fatalf("server received FCs %v, registers %v; want only the read", fcs, regs)
	}
}

// rawTCPSegment is an IPv4 TCP segment without payload.
func rawTCPSegment(src, dst net.IP, sport, dport uint16, seq uint32, flags uint8) []byte {
	src4, dst4 := src.To4(), dst.To4()
	tcp := make([]byte, 20)
	binary.BigEndian.PutUint16(tcp[0:], sport)
	binary.BigEndian.PutUint16(tcp[2:], dport)
	binary.BigEndian.PutUint32(tcp[4:], seq)
	tcp[12] = 5 << 4
	tcp[13] = flags
	binary.BigEndian.PutUint16(tcp[14:], 1024)
	pseudo := append(append(append([]byte(nil), src4...), dst4...), 0, unix.IPPROTO_TCP, 0, byte(len(tcp)))
	binary.BigEndian.PutUint16(tcp[16:], inetChecksum(append(pseudo, tcp...)))
	ip := []byte{0x45, 0, 0, byte(20 + len(tcp)), 0, 0, 0, 0, 64, unix.IPPROTO_TCP, 0, 0}
	ip = append(append(ip, src4...), dst4...)
	binary.BigEndian.PutUint16(ip[10:], inetChecksum(ip))
	return append(ip, tcp...)
}

func inetChecksum(b []byte) uint16 {
	var sum uint32
	for i := 0; i+1 < len(b); i += 2 {
		sum += uint32(binary.BigEndian.Uint16(b[i:]))
	}
	if len(b)%2 == 1 {
		sum += uint32(b[len(b)-1]) << 8
	}
	for sum>>16 != 0 {
		sum = sum&0xFFFF + sum>>16
	}
	return ^uint16(sum)
}

// sendRaw sends an IPv4 packet with its own header from this namespace.
func sendRaw(pkt []byte, dst net.IP) error {
	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_RAW, unix.IPPROTO_RAW)
	if err != nil {
		return err
	}
	defer unix.Close(fd)
	to := &unix.SockaddrInet4{}
	copy(to.Addr[:], dst.To4())
	return unix.Sendto(fd, pkt, 0, to)
}
