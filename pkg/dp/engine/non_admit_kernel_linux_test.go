// SPDX-License-Identifier: Apache-2.0
//go:build linux

package engine

import (
	"encoding/binary"
	"fmt"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/tonylturner/containd/pkg/dp/rules"
)

// Run through scripts/gate-kernel-tests.sh in a disposable Linux container.
// Both the first non-admitting repeat and TCP's retransmissions must stop
// before the receiver; testing only a synthetic marked repeat misses replay
// of bytes that userspace has already consumed.
func TestKernelNonAdmitRetransmission(t *testing.T) {
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
	startKernelEngine(t, ctx, rules.Snapshot{Default: rules.ActionDeny, DPIMode: "enforce",
		Firewall: []rules.Entry{
			scope("coil", "502", rules.ICSPredicate{Protocol: "modbus", Mode: "enforce",
				FunctionCode: []uint8{5}, UnitID: &unit, Addresses: []string{"7-7"}, Direction: "request"}),
			scope("read-monitor", "502", rules.ICSPredicate{Protocol: "modbus", Mode: "monitor", FunctionCode: []uint8{3}}),
			scope("iec-monitor", "2404", rules.ICSPredicate{Protocol: "iec104", Mode: "monitor"}),
		}})
	admissionNFT(t, `add counter inet containd_policy nonadmit_test
insert rule inet containd_policy forward meta mark & 0x10000000 != 0 counter name nonadmit_test
`)
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
			reply := make([]byte, 12)
			if err := c.conn.SetReadDeadline(time.Now().Add(fcReplyWait)); err != nil {
				t.Fatal(err)
			}
			if _, err := io.ReadFull(c.conn, reply); err != nil {
				t.Fatal(err)
			}
			if binary.BigEndian.Uint16(reply[10:]) != value || srv.received(c.src) != 12 {
				t.Fatalf("valid FC5 was not delivered: %x", reply)
			}
		})
	}
}
