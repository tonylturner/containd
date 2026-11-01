// SPDX-License-Identifier: Apache-2.0

package rules

import "testing"

func TestICSContextPrecedence(t *testing.T) {
	for _, protocol := range []string{"dnp3", "cip", ProtocolIEC104} {
		t.Run(protocol, func(t *testing.T) {
			first, second := ICSPredicate{Protocol: protocol}, ICSPredicate{Protocol: protocol}
			a, b := ICSContext{Protocol: protocol}, ICSContext{Protocol: protocol}
			switch protocol {
			case "dnp3":
				first.Groups, second.Groups = []int{1}, []int{2}
				a.Group, b.Group = u8(1), u8(2)
			case "cip":
				first.Tags, second.Tags = []string{"A"}, []string{"B"}
				a.Symbol, b.Symbol = []string{"A"}, []string{"B"}
			case ProtocolIEC104:
				first.COT, second.COT = []int{6}, []int{7}
				a.IEC104, b.IEC104 = &IEC104Context{COT: u8(6)}, &IEC104Context{COT: u8(7)}
			}
			evaluate := func(ev *Evaluator, ctx EvalContext) (Action, *Entry) {
				if protocol == ProtocolIEC104 {
					return ev.EvaluateIEC104(ctx)
				}
				return ev.EvaluateMatch(ctx)
			}
			ev := NewEvaluator(&Snapshot{DPIMode: "enforce", Default: ActionDeny, Firewall: []Entry{
				{ID: "deny-first", Action: ActionDeny, ICS: first},
				{ID: "allow-a", Action: ActionAllow, ICS: first},
				{ID: "allow-b", Action: ActionAllow, ICS: second},
			}})
			// The caller judges every context separately. No single rule needs
			// to cover both objects; the earlier matching DENY wins.
			for i, obj := range []ICSContext{a, b} {
				wantID := []string{"deny-first", "allow-b"}[i]
				wantAction := []Action{ActionDeny, ActionAllow}[i]
				if action, entry := evaluate(ev, EvalContext{ICS: &obj}); action != wantAction || entry == nil || entry.ID != wantID {
					t.Fatalf("context %d = %s by %v, want %s", i, action, entry, wantID)
				}
			}
			onlyA := NewEvaluator(&Snapshot{DPIMode: "enforce", Default: ActionDeny, Firewall: []Entry{
				{ID: "allow-a", Action: ActionAllow, ICS: first},
			}})
			if action, entry := evaluate(onlyA, EvalContext{ICS: &b}); action != ActionDeny || entry != nil {
				t.Fatalf("uncovered context = %s by %v", action, entry)
			}
			broad := ICSPredicate{}
			if protocol == ProtocolIEC104 {
				broad.Protocol = protocol // generic L4 ALLOW stays outside the IEC envelope
			}
			ev = NewEvaluator(&Snapshot{DPIMode: "enforce", Firewall: []Entry{
				{ID: "a-deny", Action: ActionDeny, ICS: first},
				{ID: "z-broad", Action: ActionAllow, ICS: broad},
			}})
			if action, entry := evaluate(ev, EvalContext{ICS: &a}); action != ActionDeny || entry == nil || entry.ID != "a-deny" {
				t.Fatalf("earlier DENY = %s by %v", action, entry)
			}
		})
	}
}
