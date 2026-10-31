// SPDX-License-Identifier: Apache-2.0
package engine

import (
	"context"
	"fmt"
	"testing"

	"github.com/tonylturner/containd/pkg/dp/capture"
	"github.com/tonylturner/containd/pkg/dp/enforce"
	"github.com/tonylturner/containd/pkg/dp/flow"
	"github.com/tonylturner/containd/pkg/dp/rules"
)

func TestQueuedRuleModesVerdictMatrix(t *testing.T) {
	for _, proto := range []string{"modbus", "iec104"} {
		for _, reverse := range []bool{false, true} {
			for _, monitor := range []rules.Action{rules.ActionAllow, rules.ActionDeny} {
				for _, active := range []rules.Action{"", rules.ActionAllow, rules.ActionDeny} {
					t.Run(fmt.Sprintf("%s/reverse=%t/%s/%s", proto, reverse, monitor, active), func(t *testing.T) {
						mid, eid := "a-monitor", "z-enforce"
						if reverse {
							mid, eid = eid, mid
						}
						snap := rules.Snapshot{Version: "queue-matrix", Default: rules.ActionDeny, Firewall: []rules.Entry{{ID: mid, Action: monitor, ICS: rules.ICSPredicate{Protocol: proto, Mode: "monitor"}}}}
						if active != "" {
							snap.Firewall = append(snap.Firewall, rules.Entry{ID: eid, Action: active, ICS: rules.ICSPredicate{Protocol: proto, Mode: "enforce"}})
						}
						var d capture.Decision
						var e *Engine
						if proto == "modbus" {
							f := newFCFlow(t, "ok", 502)
							e = f.e
							e.compiler = nil
							if err := e.ApplyRules(context.Background(), snap); err != nil {
								t.Fatal(err)
							}
							f.observeOnly = active == ""
							f.syn()
							pkt := connSegment(false, f.client, 502, f.isn, ackPsh, modbusADU(1, 3, 0, 2))
							pkt.Token = capture.NewToken(1, firstCommandTokens.Add(1))
							pkt.Mark, pkt.HasMark = 0x020000ab, true
							d = e.HandlePacket(pkt)
						} else {
							h := newIECConformanceHarness(t, "monitor", "tolerant", iecBroadPolicy("monitor"))
							e = h.e
							if err := e.ApplyRules(context.Background(), snap); err != nil {
								t.Fatal(err)
							}
							// A new connection observes the new policy from its SYN.
							h.cport++
							h.policy.mode = "enforce"
							if active == "" {
								h.policy.mode = "monitor"
							}
							h.handshake()
							pkt := h.pkt(true, ackPsh, h.cSeq, h.sSeq, apdu(46, 6, 1, 2001, 2))
							pkt.Mark, pkt.HasMark = 0x020000ab, true
							d = e.HandlePacket(pkt)
						}
						want := capture.Repeat
						if active == rules.ActionAllow {
							want = capture.Accept
						}
						if active == rules.ActionDeny {
							want = capture.Drop
						}
						if d.Action != want || len(d.Resolved) != 0 {
							t.Fatalf("decision=%+v want %v", d, want)
						}
						if active == "" && d.Mark != enforce.ObservedMark|0xab {
							t.Fatalf("mark %#x", d.Mark)
						}
						counts := e.ShadowCounters()
						if len(counts.Rules) != 1 || counts.Rules[0].ShadowMatches != 1 {
							t.Fatalf("counts=%+v", counts)
						}
					})
				}
			}
		}
	}
}

func TestQueuedScopeUsesPostDNATCoordinates(t *testing.T) {
	entry := clientToServer("backend", "502", rules.ActionDeny, rules.ICSPredicate{Protocol: "modbus", Mode: "enforce"})
	e, _ := newEnforceEngine(t, rules.ActionAllow, entry)
	for _, state := range natPolicyStates(policyNAT()) {
		pkt := capture.Packet{Transport: "tcp", SrcPort: state.Key.SrcPort, DstPort: state.Key.DstPort}
		if !e.enforcingPacketScope(pkt, state) {
			t.Fatal("missed post-DNAT service scope")
		}
		e.rememberDeniedTCP(state.Key, state.ServiceKey())
		forged := &flow.State{Key: state.Key.Reversed()}
		forged.Key.Dir = flow.DirForward
		if !e.enforcingPacketScope(pkt, forged) {
			t.Fatal("reverse SYN changed the denied post-DNAT scope")
		}
	}
}

func TestQueuedObservationRepeatsAfterEnforceScopeRemoved(t *testing.T) {
	f := newFCFlow(t, "ok", 502)
	f.syn()
	data := modbusADU(1, 6, 1, 42)
	if d := f.decide(0, ackPsh, data); d.Action != capture.Drop {
		t.Fatalf("initial enforce verdict: %+v", d)
	}
	f.e.compiler = nil
	snap := learnPolicy()
	if err := f.e.ApplyRules(context.Background(), snap); err != nil {
		t.Fatal(err)
	}
	// Historical session state is not a currently applicable enforce scope.
	if d := f.decide(0, ackPsh, data); d.Action != capture.Repeat || d.Mark != enforce.ObservedMark {
		t.Fatalf("removed enforce scope still owns admission: %+v", d)
	}
}
