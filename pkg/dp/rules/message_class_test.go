// SPDX-License-Identifier: Apache-2.0

package rules

import (
	"fmt"
	"testing"
)

func TestDS34ClassSchemaMatcher(t *testing.T) {
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

func TestDS34ClassSchemaLiveMatcherUnchanged(t *testing.T) {
	if EvaluatorVersion != "ics-4" {
		t.Fatal("evaluator version changed before class integration")
	}
	for _, protocol := range []string{"dnp3", ProtocolIEC104} {
		for _, class := range []MessageClass{ClassUnknown, ClassRequest, ClassSolicited, ClassAutonomous, ClassSession} {
			ctx := EvalContext{ICS: &ICSContext{Protocol: protocol, MessageClass: class, IEC104: &IEC104Context{}}}
			for _, selector := range []string{"", "autonomous", "session"} {
				entry := Entry{ID: "allow", Action: ActionAllow, ICS: ICSPredicate{Protocol: protocol, Mode: "enforce", MessageClass: selector}}
				if !PreviewMatch(entry, ctx) {
					t.Fatalf("class restricted live predicate: %s/%s/%s", protocol, class, selector)
				}
				e := NewEvaluator(&Snapshot{Default: ActionDeny, Firewall: []Entry{entry}})
				action, winner := e.EvaluateMessage(ctx, false)
				if protocol == ProtocolIEC104 {
					action, winner = e.EvaluateIEC104Enforcing(ctx)
				}
				if action != ActionAllow || winner == nil || winner.ID != entry.ID {
					t.Fatalf("class restricted live decision: %s/%s/%s = %s", protocol, class, selector, action)
				}
			}
		}
	}
}
