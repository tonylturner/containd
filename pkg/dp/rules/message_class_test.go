// SPDX-License-Identifier: Apache-2.0

package rules

import (
	"fmt"
	"testing"
)

func TestPairingClassSchemaMatcher(t *testing.T) {
	for _, class := range []MessageClass{"", ClassUnknown, ClassRequest, ClassSolicited, ClassAutonomous, ClassSession} {
		for _, selector := range []string{"", "autonomous", "session", "invalid"} {
			for _, action := range []Action{ActionAllow, ActionDeny, ActionReset} {
				for _, monitor := range []bool{false, true} {
					t.Run(fmt.Sprintf("%s/%s/%s/%v", class, selector, action, monitor), func(t *testing.T) {
						p := ICSPredicate{Protocol: "dnp3", MessageClass: selector}
						c := &ICSContext{Protocol: "dnp3", MessageClass: class}
						want := selector == "" && (monitor || action != ActionAllow || class == ClassRequest || class == ClassSolicited)
						if selector != "" {
							want = (selector == "autonomous" || selector == "session") && selector == string(class)
						}
						if got := MatchMessageClass(p, c, action, monitor); got != want {
							t.Fatalf("got %v, want %v", got, want)
						}
					})
				}
			}
		}
	}
	for _, protocol := range []string{"", "cip"} {
		if !MatchMessageClass(ICSPredicate{Protocol: protocol}, nil, ActionAllow, false) {
			t.Fatal("transport/CIP semantics changed")
		}
	}
	if MatchMessageClass(ICSPredicate{Protocol: "dnp3"}, nil, ActionAllow, false) ||
		MatchMessageClass(ICSPredicate{Protocol: "dnp3", MessageClass: "session"}, nil, ActionDeny, true) {
		t.Fatal("missing context matched a constrained class")
	}
}

func TestPairingLiveMessageClasses(t *testing.T) {
	for _, protocol := range []string{"modbus", "dnp3", ProtocolIEC104} {
		for _, class := range []MessageClass{ClassUnknown, ClassRequest, ClassSolicited, ClassAutonomous, ClassSession} {
			for _, mode := range []string{"monitor", "enforce", ""} {
				for _, global := range []string{"monitor", "enforce"} {
					for _, selector := range []string{"", "autonomous", "session"} {
						ctx := EvalContext{ICS: &ICSContext{Protocol: protocol, MessageClass: class, IEC104: &IEC104Context{}}}
						entry := Entry{ID: "allow", Action: ActionAllow, ICS: ICSPredicate{Protocol: protocol, Mode: mode, MessageClass: selector}}
						evaluator := NewEvaluator(&Snapshot{DPIMode: global, Firewall: []Entry{entry}})
						want := MatchMessageClass(entry.ICS, ctx.ICS, entry.Action, MonitorICS(entry, global))
						if got := evaluator.AnyMatch(ctx) != nil; got != want {
							t.Fatalf("%s/%s/%s/%s/%s got %v want %v", protocol, class, mode, global, selector, got, want)
						}
					}
				}
			}
		}
	}
}
