// SPDX-License-Identifier: Apache-2.0

package rules

import "testing"

func boolPtr(v bool) *bool { return &v }

// Every selector has an independent positive, changed value and absent value.
// Check matching, not just verdicts: an unmatched DENY also defaults to DENY
// in many policies and would otherwise conceal a broken selector.
func TestICSSelectors(t *testing.T) {
	cases := []struct {
		name              string
		protocol          string
		pred              ICSPredicate
		positive, changed ICSContext
	}{
		{"master", "dnp3", ICSPredicate{Masters: []uint16{7, 0}},
			ICSContext{Master: u16(0)}, ICSContext{Master: u16(1)}},
		{"outstation", "dnp3", ICSPredicate{Outstations: []uint16{0, 65519}},
			ICSContext{Outstation: u16(65519)}, ICSContext{Outstation: u16(1)}},
		{"group", "dnp3", ICSPredicate{Groups: []int{0, 255}},
			ICSContext{Group: u8(255)}, ICSContext{Group: u8(1)}},
		{"variation", "dnp3", ICSPredicate{Variations: []int{1, 255}},
			ICSContext{Variation: u8(255)}, ICSContext{Variation: u8(2)}},
		{"point index", "dnp3", ICSPredicate{Groups: []int{1}, Addresses: []string{"0xFFFFFFFE-0xFFFFFFFF"}},
			ICSContext{Group: u8(1), Spans: []AddressSpan{span(0xFFFFFFFF, 0xFFFFFFFF)}},
			ICSContext{Group: u8(1), Spans: []AddressSpan{span(0xFFFFFFFD, 0xFFFFFFFD)}}},
		{"class", "cip", ICSPredicate{ObjectClasses: []uint16{1, 0}},
			ICSContext{ObjectClass: 0, HasObjectClass: true}, ICSContext{ObjectClass: 2, HasObjectClass: true}},
		{"instance", "cip", ICSPredicate{Instances: []uint16{1, 0}},
			ICSContext{Instance: u16(0)}, ICSContext{Instance: u16(2)}},
		{"attribute", "cip", ICSPredicate{Attributes: []uint16{1, 65535}},
			ICSContext{Attribute: u16(65535)}, ICSContext{Attribute: u16(2)}},
		{"tag", "cip", ICSPredicate{Tags: []string{"Unused", "Program:Main.Pump"}},
			ICSContext{Symbol: []string{"program:MAIN", "PUMP", "Speed"}},
			ICSContext{Symbol: []string{"Program:Main", "Pumps", "Speed"}}},
	}
	for _, tc := range cases {
		for _, action := range []Action{ActionAllow, ActionDeny} {
			t.Run(tc.name+"/"+string(action), func(t *testing.T) {
				pred := tc.pred
				pred.Protocol = tc.protocol
				entry := Entry{ICS: pred, Action: action}
				for name, obj := range map[string]ICSContext{
					"positive": tc.positive, "changed": tc.changed, "absent": {},
				} {
					obj.Protocol = tc.protocol
					if got := PreviewMatch(entry, EvalContext{ICS: &obj}); got != (name == "positive") {
						t.Errorf("%s match = %v", name, got)
					}
				}
			})
		}
	}
}

func TestDNP3VariationZero(t *testing.T) {
	for _, tc := range []struct {
		name        string
		list        []int
		wire        *uint8
		allow, deny bool
	}{
		{"omitted selector missing wire", nil, nil, true, true},
		{"omitted selector zero", nil, u8(0), true, true},
		{"zero explicitly allowed", []int{0}, u8(0), true, true},
		{"zero is not concrete", []int{0}, u8(1), false, false},
		{"concrete selector unknown wire", []int{1}, u8(0), false, true},
		{"zero and concrete", []int{0, 1}, u8(1), true, true},
		{"missing is not wire zero", []int{0}, nil, false, false},
		{"concrete mismatch", []int{1}, u8(2), false, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			for _, action := range []Action{ActionAllow, ActionDeny} {
				want := tc.allow
				if action == ActionDeny {
					want = tc.deny
				}
				entry := Entry{Action: action, ICS: ICSPredicate{Protocol: "dnp3", Variations: tc.list}}
				ctx := EvalContext{ICS: &ICSContext{Protocol: "dnp3", Variation: tc.wire}}
				if got := PreviewMatch(entry, ctx); got != want {
					t.Errorf("%s match = %v, want %v", action, got, want)
				}
			}
		})
	}
}

func TestCIPTagOverlap(t *testing.T) {
	for _, tc := range []struct {
		name        string
		symbol      []string
		allow, deny bool
	}{
		{"equal ignoring case", []string{"a", "b"}, true, true},
		{"subtree", []string{"A", "B", "C"}, true, true},
		{"aggregate", []string{"A"}, false, true},
		{"not a segment prefix", []string{"A", "BC"}, false, false},
		{"different root", []string{"AA", "B"}, false, false},
		{"logical symbol class", nil, false, false},
		{"empty symbol", []string{}, false, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			for _, action := range []Action{ActionAllow, ActionDeny} {
				want := tc.allow
				if action == ActionDeny {
					want = tc.deny
				}
				entry := Entry{Action: action, ICS: ICSPredicate{Protocol: "cip", Tags: []string{"A.B"}}}
				obj := ICSContext{Protocol: "cip", Symbol: tc.symbol, HasObjectClass: true, ObjectClass: 0x6b}
				if got := PreviewMatch(entry, EvalContext{ICS: &obj}); got != want {
					t.Errorf("%s match = %v, want %v", action, got, want)
				}
			}
		})
	}
}

func TestCIPTagMatchingAllocatesNothing(t *testing.T) {
	ev := NewEvaluator(&Snapshot{Firewall: []Entry{{
		ID: "tag", Action: ActionDeny, ICS: ICSPredicate{Protocol: "cip", Tags: []string{"Program:Main.A.B"}},
	}}})
	ctx := EvalContext{ICS: &ICSContext{Protocol: "cip", Symbol: []string{"program:MAIN", "a"}}}
	if allocs := testing.AllocsPerRun(100, func() {
		if action, entry := ev.EvaluateMatch(ctx); action != ActionDeny || entry == nil {
			t.Fatal("aggregate tag operation did not match")
		}
	}); allocs != 0 {
		t.Fatalf("tag matching allocated %v times per call", allocs)
	}
}

func TestDNP3PointSpans(t *testing.T) {
	for _, tc := range []struct {
		name        string
		spans       []AddressSpan
		unknown     bool
		allow, deny bool
	}{
		{"adjacent union at max", []AddressSpan{span(4294967293, 4294967295)}, false, true, true},
		{"zero", []AddressSpan{span(0, 0)}, false, true, true},
		{"one point outside", []AddressSpan{span(0, 0), span(10, 10)}, false, false, true},
		{"crossing", []AddressSpan{span(4294967292, 4294967295)}, false, false, true},
		{"outside", []AddressSpan{span(10, 10)}, false, false, false},
		{"missing", nil, false, false, false},
		{"unbounded", nil, true, false, true},
		{"unknown with known points", []AddressSpan{span(0, 0)}, true, false, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			for _, action := range []Action{ActionAllow, ActionDeny} {
				want := tc.allow
				if action == ActionDeny {
					want = tc.deny
				}
				entry := Entry{Action: action, ICS: ICSPredicate{Protocol: "dnp3", Groups: []int{1},
					Addresses: []string{"0", "4294967293", "4294967294-4294967295"}}}
				obj := ICSContext{Protocol: "dnp3", Group: u8(1), Spans: tc.spans, SpansUnknown: tc.unknown}
				if got := PreviewMatch(entry, EvalContext{ICS: &obj}); got != want {
					t.Errorf("%s match = %v, want %v", action, got, want)
				}
			}
		})
	}
	if ICSAddressMax("dnp3") != 4294967295 {
		t.Fatal("DNP3 addresses must preserve all 32 bits")
	}
	if _, _, err := ParseICSAddressSpec("4294967296"); err == nil {
		t.Fatal("accepted a point index beyond 32 bits")
	}
}

func TestIEC104NewSelectors(t *testing.T) {
	for _, tc := range []struct {
		name              string
		pred              ICSPredicate
		positive, changed IEC104Context
	}{
		{"command zero state", ICSPredicate{CommandStates: []int{0}}, IEC104Context{CommandState: u8(0)}, IEC104Context{CommandState: u8(1)}},
		{"command state", ICSPredicate{CommandStates: []int{1}}, IEC104Context{CommandState: u8(1)}, IEC104Context{CommandState: u8(2)}},
		{"command qualifier", ICSPredicate{CommandQualifiers: []int{0}}, IEC104Context{CommandQualifier: u8(0)}, IEC104Context{CommandQualifier: u8(31)}},
		{"cot", ICSPredicate{COT: []int{1, 63}}, IEC104Context{COT: u8(63)}, IEC104Context{COT: u8(2)}},
		{"originator", ICSPredicate{Originators: []int{255, 0}}, IEC104Context{Originator: u8(0)}, IEC104Context{Originator: u8(1)}},
		{"negative true", ICSPredicate{Negative: boolPtr(true)}, IEC104Context{Negative: boolPtr(true)}, IEC104Context{Negative: boolPtr(false)}},
		{"negative false", ICSPredicate{Negative: boolPtr(false)}, IEC104Context{Negative: boolPtr(false)}, IEC104Context{Negative: boolPtr(true)}},
		{"test true", ICSPredicate{Test: boolPtr(true)}, IEC104Context{Test: boolPtr(true)}, IEC104Context{Test: boolPtr(false)}},
		{"test false", ICSPredicate{Test: boolPtr(false)}, IEC104Context{Test: boolPtr(false)}, IEC104Context{Test: boolPtr(true)}},
		{"select", ICSPredicate{SelectExecute: "select"}, IEC104Context{Select: boolPtr(true)}, IEC104Context{Select: boolPtr(false)}},
		{"execute", ICSPredicate{SelectExecute: "execute"}, IEC104Context{Select: boolPtr(false)}, IEC104Context{Select: boolPtr(true)}},
	} {
		for _, action := range []Action{ActionAllow, ActionDeny, ActionReset, ActionRateLimit, ActionTag} {
			t.Run(tc.name+"/"+string(action), func(t *testing.T) {
				entry := iecEntry("selector", action, tc.pred)
				for name, obj := range map[string]IEC104Context{
					"positive": tc.positive, "changed": tc.changed, "absent": {},
					"S frame": {APCIType: "S"}, "U frame": {APCIType: "U"},
				} {
					ctx := sessionCtx("request", obj)
					if got := PreviewMatch(entry, ctx); got != (name == "positive") {
						t.Errorf("%s match = %v", name, got)
					}
					_, matched := NewEvaluator(&Snapshot{Firewall: []Entry{entry}}).EvaluateIEC104(ctx)
					if (matched != nil) != (name == "positive" && action != ActionRateLimit && action != ActionTag) {
						t.Errorf("%s dedicated IEC evaluator match = %v", name, matched)
					}
				}
			})
		}
	}
}

func TestIEC104UnknownObjectDoesNotInventCommandFields(t *testing.T) {
	for _, action := range []Action{ActionAllow, ActionDeny, ActionReset, ActionRateLimit, ActionTag} {
		for _, pred := range []ICSPredicate{{CommandStates: []int{1}}, {CommandQualifiers: []int{0}}} {
			pred.IOA = []IOARange{{Start: 7, End: 7}}
			ctx := sessionCtx("request", IEC104Context{})
			ctx.ICS.ObjectUnknown = true
			if PreviewMatch(iecEntry("unknown-command", action, pred), ctx) {
				t.Fatalf("unknown fields matched %s", action)
			}
		}
	}
}
