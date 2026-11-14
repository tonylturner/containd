// SPDX-License-Identifier: Apache-2.0
package engine

import (
	"fmt"
	"github.com/tonylturner/containd/pkg/dp/capture"
	"github.com/tonylturner/containd/pkg/dp/rules"
	"testing"
)

// No receiver-delivery claim is made from these decisions: the live harness
// captures both receiver interfaces. Here the invariant is packet atomicity
// and residency until the actual submission callback, including one-byte I/O.
func TestDS34Assurance(t *testing.T) {
	for _, p := range runtimePairCases() {
		for _, reply := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/one-byte/reply=%t", p.protocol, reply), func(t *testing.T) {
				e := runtimePairEngine(t, rules.Snapshot{Default: rules.ActionDeny, DPIMode: "enforce", Firewall: []rules.Entry{runtimePairRule(p, "enforce")}}, true)
				inlineHandshake(t, e, 41000, p.port)
				wire, seq := p.request, uint32(100)
				if reply {
					req := runtimePairPacket(p, false, 100, p.request)
					if d := e.HandlePacket(req); d.Action != capture.Repeat {
						t.Fatal(d)
					}
					e.hooks.onVerdict(req.Token, capture.VerdictRepeat, nil)
					wire, seq = p.reply, 500
				}
				var held []capture.Token
				for i, b := range wire {
					pkt := runtimePairPacket(p, reply, seq+uint32(i), []byte{b})
					d := e.HandlePacket(pkt)
					if i < len(wire)-1 {
						if d.Action != capture.Hold || len(d.Resolved) != 0 {
							t.Fatalf("byte %d released prefix: %+v", i, d)
						}
						held = append(held, pkt.Token)
						continue
					}
					if d.Action != capture.Repeat || len(d.Resolved) != len(held) {
						t.Fatalf("final byte: %+v", d)
					}
					for j, r := range d.Resolved {
						if r.Token != held[j] || r.Verdict != capture.VerdictRepeat {
							t.Fatalf("resolution %d: %+v", j, r)
						}
					}
					before := e.budget.Status()
					if before.ByCategory["held"] == 0 {
						t.Fatal("released tokens refunded before submission")
					}
					for _, tok := range held {
						e.hooks.onVerdict(tok, capture.VerdictRepeat, nil)
					}
					e.hooks.onVerdict(pkt.Token, capture.VerdictRepeat, nil)
					if e.budget.Status().ByCategory["held"] != 0 {
						t.Fatal("submitted holds retained credit")
					}
					t.Logf("bytes=%d held-tokens=%d budget-high-water=%d", len(wire), len(held), before.HighWater)
				}
			})
		}
	}
	// This includes nonempty IEC spontaneous data, not a session-control stand-in.
	for _, mode := range []string{"monitor", "enforce"} {
		t.Run("legacy-autonomous/"+mode, func(t *testing.T) {
			p := runtimePairCases()[2]
			e := runtimePairEngine(t, rules.Snapshot{Default: rules.ActionAllow, DPIMode: mode, Firewall: []rules.Entry{runtimePairRule(p, mode)}}, true)
			inlineHandshake(t, e, 41000, p.port)
			d := e.HandlePacket(runtimePairPacket(p, true, 500, apdu(1, 3, 1, 101, 1)))
			want := capture.Drop
			if mode == "monitor" {
				want = capture.Repeat
			}
			if d.Action != want || mode == "enforce" && d.Reason != string(autonomousRequired) {
				t.Fatalf("autonomous: %+v", d)
			}
		})
	}
}
