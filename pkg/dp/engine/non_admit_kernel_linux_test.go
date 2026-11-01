// SPDX-License-Identifier: Apache-2.0
//go:build linux

package engine

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/tonylturner/containd/pkg/dp/rules"
)

// Run through scripts/gate-kernel-tests.sh in a disposable Linux container.
// Both the first non-admitting repeat and TCP's retransmissions must stop
// before the receiver; testing only a synthetic marked repeat misses replay
// of bytes that userspace has already consumed.
func nonAdmitKernelLab(t *testing.T) (context.Context, *Engine, *kernelServer) {
	t.Helper()
	ctx := newFirstCommandLab(t)
	srv := startKernelServer(t, 502, func(_ string, b []byte) (int, []byte, error) {
		if len(b) < 12 {
			return 0, nil, nil
		}
		if binary.BigEndian.Uint16(b[10:12]) == 0x1234 {
			return 12, []byte{0, 1, 0, 0, 0, 3, 1, 0x85, 3}, nil
		}
		return 12, append([]byte(nil), b[:12]...), nil
	})
	unit := uint8(1)
	scope := func(id, port string, ics rules.ICSPredicate) rules.Entry {
		return rules.Entry{ID: id, Action: rules.ActionAllow,
			Sources: []string{"198.18.50.0/24"}, Destinations: []string{fcServerIP + "/32"},
			Protocols: []rules.Protocol{{Name: "tcp", Port: port}}, ICS: ics}
	}
	e := startKernelEngine(t, ctx, rules.Snapshot{Default: rules.ActionDeny, DPIMode: "enforce",
		Firewall: []rules.Entry{
			scope("coil", "502", rules.ICSPredicate{Protocol: "modbus", Mode: "enforce",
				FunctionCode: []uint8{5}, UnitID: &unit, Addresses: []string{"7-7"}, Direction: "request"}),
			scope("read-monitor", "502", rules.ICSPredicate{Protocol: "modbus", Mode: "monitor", FunctionCode: []uint8{3}}),
			scope("iec-monitor", "2404", rules.ICSPredicate{Protocol: "iec104", Mode: "monitor"}),
		}})
	admissionNFT(t, `add counter inet containd_policy nonadmit_test
insert rule inet containd_policy forward meta mark & 0x10000000 != 0 counter name nonadmit_test
`)
	return ctx, e, srv
}

func TestKernelNonAdmitRetransmission(t *testing.T) {
	ctx, e, srv := nonAdmitKernelLab(t)
	// Resets are best effort. With the injector unavailable, real TCP
	// retransmissions must still carry the non-admitting continuation.
	e.iec.health.fault(faultInjector, "test: reset injector unavailable")
	for i, value := range []uint16{0, 0xff00, 0x1234} {
		t.Run(fmt.Sprintf("%04x", value), func(t *testing.T) {
			c := dialFirstCommand(ctx, t, fmt.Sprintf("198.18.50.%d", 10+i))
			c.write(c.next(5, 7, value))
			if value == 0x1234 {
				c.expectSilence() // also proves the TCP stack retransmitted
				if n := srv.received(c.src); n != 0 {
					t.Fatalf("reserved FC5 reached receiver: %d bytes", n)
				}
				out := fcRun(ctx, t, "nft", "list", "counter", "inet", "containd_policy", "nonadmit_test")
				_, tail, ok := strings.Cut(out, "packets ")
				var packets uint64
				if !ok {
					t.Fatalf("missing repeat counter: %s", out)
				}
				if _, err := fmt.Sscan(tail, &packets); err != nil || packets < 2 {
					t.Fatalf("first packet and retry did not both repeat NonAdmit: %s (%v)", out, err)
				}
				return
			}
			expectCoilReply(t, c, value)
			if srv.received(c.src) != 12 {
				t.Fatal("valid FC5 was not delivered")
			}
		})
	}
}

func TestKernelNonAdmitResetReconnect(t *testing.T) {
	ctx, _, srv := nonAdmitKernelLab(t)
	c := dialFirstCommand(ctx, t, "198.18.50.13")
	port := c.localPort()
	c.write(c.next(5, 7, 0x1234))
	c.expectReset() // bounded by fcReplyWait, without an exception response
	if n := srv.received(c.src); n != 0 {
		t.Fatalf("reserved FC5 reached receiver: %d bytes", n)
	}
	if ends := srv.ended(t, c.src, 1); !errors.Is(ends[0], syscall.ECONNRESET) {
		t.Fatalf("receiver connection ended with %v, want reset", ends[0])
	}
	if err := c.conn.Close(); err != nil {
		t.Fatal(err)
	}
	// Reuse the exact tuple: delayed old reset jobs or stale failed-stream
	// state must not damage the next incarnation.
	next, took := dialFrom(ctx, t, c.src, port, 502)
	if took > fcReconnectBound {
		t.Fatalf("reconnect took %v", took)
	}
	for _, value := range []uint16{0, 0xff00} {
		next.write(next.next(5, 7, value))
		expectCoilReply(t, next, value)
	}
	if n := srv.received(c.src); n != 24 {
		t.Fatalf("reconnect received %d bytes, want valid OFF and ON only", n)
	}
}

func expectCoilReply(t *testing.T, c *fcClient, value uint16) {
	t.Helper()
	reply := make([]byte, 12)
	if err := c.conn.SetReadDeadline(time.Now().Add(fcReplyWait)); err != nil {
		t.Fatal(err)
	}
	if _, err := io.ReadFull(c.conn, reply); err != nil {
		t.Fatal(err)
	}
	if binary.BigEndian.Uint16(reply[10:]) != value {
		t.Fatalf("valid FC5 was not echoed: %x", reply)
	}
}
