// SPDX-License-Identifier: Apache-2.0
package rules

import (
	"fmt"
	"testing"
	"time"
)

// All 36 pairs include both plain/ICS partitions and every terminal action,
// even the validation-invalid ICS RESET: the evaluator must not sort by action.
func TestOrderedTerminalPairs(t *testing.T) {
	var entries []Entry
	for _, ics := range []bool{false, true} {
		for _, action := range []Action{ActionAllow, ActionDeny, ActionReset} {
			e := tcpEntry(fmt.Sprintf("%v-%s", ics, action), action, "502")
			if ics {
				e.ICS = ICSPredicate{Protocol: "modbus", FunctionCode: []uint8{3}, Mode: "enforce"}
			}
			entries = append(entries, e)
		}
	}
	ctx := l4Ctx("198.51.100.1", "10.0.0.8", "tcp", "502")
	ctx.ICS = &ICSContext{Protocol: "modbus", HasFunctionCode: true, FunctionCode: 3}
	for _, first := range entries {
		for _, second := range entries {
			t.Run(first.ID+"/"+second.ID, func(t *testing.T) {
				ev := NewEvaluator(&Snapshot{Default: ActionDeny, Firewall: []Entry{first, second}})
				action, winner := ev.EvaluateMessage(ctx, false)
				if action != first.Action || ruleID(winner) != first.ID {
					t.Fatalf("S4 = %s by %s", action, ruleID(winner))
				}
				for _, inspection := range []bool{false, true} {
					want := first.Action
					if inspection && first.ICS.Protocol != "" {
						want = ActionAllow
					}
					action, winner = ev.EvaluateTransport(ctx, inspection)
					if action != want || ruleID(winner) != first.ID {
						t.Fatalf("S2 inspection=%v = %s by %s", inspection, action, ruleID(winner))
					}
				}
			})
		}
	}
}

func TestMonitorNeverDecidesOrderedPolicy(t *testing.T) {
	for _, action := range []Action{ActionAllow, ActionDeny, ActionReset} {
		for _, def := range []Action{ActionAllow, ActionDeny} {
			monitor := Entry{ID: "monitor", Action: action, ICS: ICSPredicate{Protocol: "modbus", Mode: "monitor"}}
			ev := NewEvaluator(&Snapshot{Default: def, Firewall: []Entry{monitor}})
			ctx := EvalContext{ICS: &ICSContext{Protocol: "modbus"}}
			for _, decision := range []func() (Action, *Entry){
				func() (Action, *Entry) { return ev.EvaluateMatch(ctx) },
				func() (Action, *Entry) { return ev.EvaluateMessage(ctx, false) },
				func() (Action, *Entry) { return ev.EvaluateTransport(ctx, true) },
				func() (Action, *Entry) { return ev.EvaluateTransport(ctx, false) },
			} {
				if got, winner := decision(); got != def || winner != nil {
					t.Fatalf("monitor %s decided %s by %v", action, got, winner)
				}
			}
			if got := ev.MonitorMatches(ctx); len(got) != 1 || got[0].ID != "monitor" {
				t.Fatal("lost monitor telemetry")
			}
		}
	}
}

func TestOrderedConditionalTransportAndMessage(t *testing.T) {
	conditional := tcpEntry("z-conditional-deny", ActionDeny, "502")
	conditional.Identities = []string{"operator"}
	conditional.Schedule = SchedulePredicate{StartTime: "09:00", EndTime: "10:00", Timezone: "UTC"}
	conditional.ICS = ICSPredicate{Protocol: "modbus", FunctionCode: []uint8{6}, Mode: "enforce"}
	ev := NewEvaluator(&Snapshot{Default: ActionDeny, Firewall: []Entry{conditional, tcpEntry("a-plain-allow", ActionAllow, "502")}})
	ctx := l4Ctx("198.51.100.1", "10.0.0.8", "tcp", "502")
	ctx.Now = time.Date(2026, 10, 31, 9, 30, 0, 0, time.UTC)
	ctx.ICS = &ICSContext{Protocol: "modbus", HasFunctionCode: true, FunctionCode: 3}
	if !ev.TransportScopeMatch(0, ctx) {
		t.Fatal("identity, schedule or message narrowed inspection")
	}
	if _, winner := ev.EvaluateTransport(ctx, true); ruleID(winner) != "a-plain-allow" {
		t.Fatal("missing identity matched")
	}
	ctx.Identities = []string{"operator"}
	if action, winner := ev.EvaluateTransport(ctx, true); action != ActionAllow || ruleID(winner) != conditional.ID {
		t.Fatal("ICS did not admit transport")
	}
	if _, winner := ev.EvaluateMessage(ctx, false); ruleID(winner) != "a-plain-allow" {
		t.Fatal("message predicate ignored")
	}
	ctx.ICS.FunctionCode = 6
	if action, winner := ev.EvaluateMessage(ctx, false); action != ActionDeny || ruleID(winner) != conditional.ID {
		t.Fatal("matching ICS denial lost")
	}
	ctx.Now = ctx.Now.Add(time.Hour)
	if _, winner := ev.EvaluateTransport(ctx, true); ruleID(winner) != "a-plain-allow" {
		t.Fatal("expired conditional did not fall through")
	}
}

func TestCapturedGenericReplyDecisions(t *testing.T) {
	ctx := EvalContext{ICS: &ICSContext{Protocol: "modbus", Direction: "response"}}
	for _, def := range []Action{ActionAllow, ActionDeny} {
		for _, action := range []Action{ActionAllow, ActionDeny, ActionReset} {
			for _, isICS := range []bool{false, true} {
				entry := Entry{ID: "explicit", Action: action}
				if isICS {
					entry.ICS = ICSPredicate{Protocol: "modbus", Mode: "enforce", Direction: "response"}
				}
				ev := NewEvaluator(&Snapshot{Default: def, Firewall: []Entry{entry}})
				if got, winner := ev.EvaluateMessage(ctx, true); got != action || ruleID(winner) != entry.ID {
					t.Fatal("explicit captured reply decision suppressed")
				}
			}
		}
		ev := NewEvaluator(&Snapshot{Default: def})
		if got, winner := ev.EvaluateMessage(ctx, true); got != ActionAllow || winner != nil {
			t.Fatal("unmatched reply default not suppressed")
		}
		if got, winner := ev.EvaluateMessage(ctx, false); got != def || winner != nil {
			t.Fatal("request default suppressed")
		}
	}
}

func TestIECPartitionConfiguredOrder(t *testing.T) {
	ctx := sessionCtx("response", iFrame(100, "system", 1, 0, true))
	for _, first := range []Action{ActionAllow, ActionDeny, ActionReset} {
		for _, second := range []Action{ActionAllow, ActionDeny, ActionReset} {
			a := iecEntry("z-first", first, ICSPredicate{Mode: "enforce"})
			b := iecEntry("a-second", second, ICSPredicate{Mode: "enforce"})
			ev := NewEvaluator(&Snapshot{Default: ActionAllow, Firewall: []Entry{{ID: "plain", Action: ActionAllow}, iecEntry("monitor", ActionAllow, ICSPredicate{Mode: "monitor"}), a, b}})
			if got, winner := ev.EvaluateIEC104Enforcing(ctx); got != first || ruleID(winner) != a.ID {
				t.Fatal("IEC partition not configured order")
			}
		}
	}
	ev := NewEvaluator(&Snapshot{Default: ActionAllow, Firewall: []Entry{{ID: "plain", Action: ActionAllow}}})
	if got, winner := ev.EvaluateIEC104Enforcing(ctx); got != ActionDeny || winner != nil {
		t.Fatal("IEC reply default not DENY")
	}
}
