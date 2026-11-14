// SPDX-License-Identifier: Apache-2.0
package engine

import (
	"context"
	"fmt"
	"testing"

	"github.com/tonylturner/containd/pkg/dp/capture"
	"github.com/tonylturner/containd/pkg/dp/dpi"
	"github.com/tonylturner/containd/pkg/dp/ics/dnp3"
	"github.com/tonylturner/containd/pkg/dp/ics/eventfields"
	"github.com/tonylturner/containd/pkg/dp/ics/modbus"
	"github.com/tonylturner/containd/pkg/dp/rules"
)

func TestDS34SharedPolicyTelemetry(t *testing.T) {
	for _, p := range firstCommandProtocols() {
		for _, mode := range []string{"enforce", "monitor"} {
			for _, strict := range []bool{false, true} {
				t.Run(fmt.Sprintf("%s/%s/strict=%t", p.name, mode, strict), func(t *testing.T) {
					f := newFCFlow(t, "ok", p.port)
					entries := []rules.Entry{{
						ID: "shadow", Action: rules.ActionAllow,
						ICS: rules.ICSPredicate{Protocol: p.name, Mode: "monitor"},
					}}
					if mode == "enforce" {
						entries = append(entries,
							rules.Entry{ID: "allow", Action: rules.ActionAllow, Log: true, ICS: rules.ICSPredicate{Protocol: p.name, Mode: "enforce"}},
							rules.Entry{ID: "later-deny", Action: rules.ActionDeny, Log: true, ICS: rules.ICSPredicate{Protocol: p.name, Mode: "enforce"}})
					}
					f.e.compiler = nil
					if err := f.e.ApplyRules(context.Background(), rules.Snapshot{Default: rules.ActionDeny, Firewall: entries}); err != nil {
						t.Fatal(err)
					}
					f.observeOnly = mode == "monitor"
					if strict {
						f.e.SetICSParsing(map[string]string{p.name: "strict"})
						var dec dpi.StreamDecoder = modbus.NewDecoder()
						if p.name == "dnp3" {
							dec = dnp3.NewDecoder()
						}
						f.e.dpiMgr = dpi.NewManager(findingDecoder{dec})
						f.e.sessions.dpi = f.e.dpiMgr
					}
					f.syn()
					wire := p.read(1)
					got := f.decide(0, ackPsh, wire)
					want := capture.Repeat
					if strict && mode == "enforce" {
						want = capture.Drop
					}
					if got.Action != want || mode == "monitor" && got.Reason != reasonPolicyNonAdmit {
						t.Fatalf("decision = %+v", got)
					}
					counts := f.e.ShadowCounters()
					if len(counts.Rules) != 1 || counts.Rules[0].RuleID != "shadow" || counts.Rules[0].ShadowMatches != 1 || counts.Rules[0].WouldAllow != 1 {
						t.Fatalf("shadow facts = %+v", counts)
					}
					wantHits := 0
					if mode == "enforce" && !strict {
						wantHits = 1
					}
					if ruleHits(f.e, "allow") != wantHits || ruleHits(f.e, "later-deny") != 0 {
						t.Fatal("ordered typed evaluation lost its winning attribution")
					}
					// Identical TCP retransmission must not evaluate or count the
					// decoded message again, even after an abort.
					retry := f.decide(0, ackPsh, wire)
					if retry.Action != want || mode == "monitor" && retry.Reason != reasonPolicyNonAdmit ||
						f.e.ShadowCounters().Rules[0].ShadowMatches != 1 || ruleHits(f.e, "allow") != wantHits {
						t.Fatalf("retry changed message facts: %+v", retry)
					}
					if strict {
						decisions := findingEvents(f.e, eventfields.KindDecision)
						n := 0
						for _, d := range decisions {
							if d.Attributes["reason"] == reasonNonconformant {
								n++
								if d.Attributes["scopeId"] == nil || d.Attributes["ruleId"] != nil {
									t.Fatalf("strict attribution = %+v", d)
								}
							}
						}
						if n != 1 || len(findingEvents(f.e, "alert")) != 1 {
							t.Fatal("strict message was lost or counted twice")
						}
					}
				})
			}
		}
	}
}

func TestExplicitDenyOfUnsupportedFunctionAttribution(t *testing.T) {
	f := newFCFlow(t, "ok", 502)
	f.syn()
	before := ruleHits(f.e, "modbus-diag-deny")
	d := f.decide(0, ackPsh, modbusADU(101, 8, 0, 0xA537))
	after := ruleHits(f.e, "modbus-diag-deny")
	t.Logf("FC8 with explicit DENY rule: %+v, rule hits %d -> %d", d, before, after)
	if after != before+1 {
		t.Errorf("explicit DENY rule got no hit; decision reason=%s", d.Reason)
	}
}
