// SPDX-License-Identifier: Apache-2.0
//go:build linux

package capture

import (
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/tonylturner/containd/pkg/dp/enforce"
	"github.com/tonylturner/containd/pkg/dp/markabi"
	"github.com/tonylturner/containd/pkg/dp/rules"
	"golang.org/x/sys/unix"
)

// Run with CONTAIND_NETNS_KERNEL_TEST=1 in an isolated Linux network namespace
// as root with CAP_NET_ADMIN and nft. It intentionally never uses queue bypass.
func TestKernelNFQueueRepeatMarkResumesFirewall(t *testing.T) {
	requireKernel(t)
	const queue = 4714
	var seen atomic.Int32
	var nonAdmit atomic.Bool
	invalidMarks := make(chan uint32, 8)
	mgr, err := NewManager(Config{Mode: "nfqueue", QueueID: queue})
	if err != nil {
		t.Fatal(err)
	}
	if err = mgr.Start(context.Background(), func(p Packet) Decision {
		if p.Invalid != "" {
			select {
			case invalidMarks <- p.Mark:
			default:
			}
			if enforce.EnvelopeMarked(p.Mark) {
				return Decision{Action: Drop}
			}
			return Decision{Action: Repeat, Mark: markabi.Continue(p.Mark, false)}
		}
		if p.Transport != "udp" {
			return Decision{Action: Drop}
		}
		if seen.Add(1) > 2 {
			return Decision{Action: Drop}
		} // bound a broken requeue loop
		if p.Mark & ^markabi.ContinuationSkbMask != 0x200000ab {
			t.Errorf("original mark %#x", p.Mark)
		}
		return Decision{Action: Repeat, Mark: markabi.Continue(p.Mark, nonAdmit.Load())}
	}); err != nil {
		t.Fatal(err)
	}
	defer mgr.Stop()
	for _, allow := range []bool{false, true} {
		t.Run(fmt.Sprint("accept=", allow), func(t *testing.T) {
			// The enforcing IEC scope admits transport even with default
			// DENY. Simulate S4's default DENY with NonAdmit, not an
			// admitting continuation that S2 is allowed to deliver.
			nonAdmit.Store(!allow)
			ln, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
			if err != nil {
				t.Fatal(err)
			}
			defer ln.Close()
			port := ln.LocalAddr().(*net.UDPAddr).Port
			installRepeatPolicy(t, queue, port, false)

			conn, err := net.DialUDP("udp4", nil, ln.LocalAddr().(*net.UDPAddr))
			if err != nil {
				t.Fatal(err)
			}
			defer conn.Close()
			raw, err := conn.SyscallConn()
			if err != nil {
				t.Fatal(err)
			}
			var markErr error
			if err := raw.Control(func(fd uintptr) { markErr = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_MARK, 0x200000ab) }); err != nil {
				t.Fatal(err)
			}
			if markErr != nil {
				t.Fatal(markErr)
			}
			before := seen.Load()
			if _, err = conn.Write([]byte("repeat")); err != nil {
				t.Fatal(err)
			}
			if err = ln.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
				t.Fatal(err)
			}
			b := make([]byte, 20)
			n, err := ln.Read(b)
			if allow && (err != nil || string(b[:n]) != "repeat") {
				t.Fatalf("receiver n=%d err=%v", n, err)
			}
			if !allow && err == nil {
				t.Fatal("S2 admitted a NonAdmit continuation")
			}
			if got := seen.Load() - before; got != 1 {
				t.Fatalf("queued %d times, want exactly once", got)
			}
		})
	}
	for _, reverse := range []bool{false, true} {
		t.Run(fmt.Sprint("invalid-mixed/reverse=", reverse), func(t *testing.T) {
			installRepeatPolicy(t, queue, 44818, reverse)
			sendExtensionSYN(t)
			select {
			case mark := <-invalidMarks:
				if !enforce.EnvelopeMarked(mark) {
					t.Fatalf("invalid TCP/2404 queued without envelope mark: %#x", mark)
				}
			case <-time.After(2 * time.Second):
				t.Fatal("extension-header packet did not reach the queue")
			}
		})
	}
}

// Use the complete compiled mixed policy. Only move its policy hook from
// forward to output to exercise it over loopback without a routing lab.
// Steering, mark guards, counters, conntrack and default verdicts stay intact.
func installRepeatPolicy(t *testing.T, queue int, port int, reverse bool) {
	t.Helper()
	mid, eid := "a-monitor", "z-enforce"
	if reverse {
		mid, eid = eid, mid
	}
	snap := &rules.Snapshot{Default: rules.ActionDeny, DPIMode: "monitor", Firewall: []rules.Entry{
		{ID: mid, Action: rules.ActionAllow, ICS: rules.ICSPredicate{Protocol: "iec104"}},
		{ID: eid, Action: rules.ActionDeny, ICS: rules.ICSPredicate{Protocol: "iec104", Mode: "enforce"}},
		{ID: "udp-monitor", Action: rules.ActionDeny, Protocols: []rules.Protocol{{Name: "udp", Port: fmt.Sprint(port)}}, ICS: rules.ICSPredicate{Protocol: "cip", Mode: "monitor"}},
	}}
	c := enforce.NewCompiler()
	c.TableName = "containd_repeat_test"
	c.QueueID = queue
	c.IEC104EnvelopeOpen = true
	text, err := c.CompileFirewall(snap)
	if err != nil {
		t.Fatal(err)
	}
	text = strings.Replace(text, "type filter hook forward priority 0;", "type filter hook output priority 0;", 1)
	if err := enforce.NewNftApplier().Apply(context.Background(), text); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { nft(t, c.DeleteTables()) })
}

func sendExtensionSYN(t *testing.T) {
	t.Helper()
	// IPv6 + hop-by-hop header + valid TCP SYN to the IEC104 service.
	packet := make([]byte, 68)
	packet[0] = 0x60
	binary.BigEndian.PutUint16(packet[4:6], 28)
	packet[7] = 64
	packet[23] = 1
	packet[39] = 1
	packet[40] = 6
	tcp := packet[48:]
	binary.BigEndian.PutUint16(tcp[0:2], 40000)
	binary.BigEndian.PutUint16(tcp[2:4], 2404)
	binary.BigEndian.PutUint32(tcp[4:8], 1)
	tcp[12] = 0x50
	tcp[13] = 2
	binary.BigEndian.PutUint16(tcp[14:16], 4096)
	pseudo := append([]byte(nil), packet[8:40]...)
	pseudo = append(pseudo, 0, 0, 0, 20, 0, 0, 0, 6)
	pseudo = append(pseudo, tcp...)
	var sum uint32
	for i := 0; i < len(pseudo); i += 2 {
		sum += uint32(binary.BigEndian.Uint16(pseudo[i : i+2]))
	}
	for sum>>16 != 0 {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	binary.BigEndian.PutUint16(tcp[16:18], ^uint16(sum))
	fd, err := unix.Socket(unix.AF_INET6, unix.SOCK_RAW, unix.IPPROTO_RAW)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(fd)
	if err := unix.Sendto(fd, packet, 0, &unix.SockaddrInet6{Addr: [16]byte{15: 1}}); err != nil {
		t.Fatal(err)
	}
}
