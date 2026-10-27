// SPDX-License-Identifier: Apache-2.0

package rules

import "testing"

func span(low, high uint32) AddressSpan { return AddressSpan{Low: low, High: high} }

// allowMatches reports whether an ALLOW with the specifications matches a
// message touching spans.
func allowMatches(specs []string, spans ...AddressSpan) bool {
	return addressMatch(ActionAllow, specs, &ICSContext{Spans: spans})
}

func addressMatch(action Action, specs []string, ics *ICSContext) bool {
	ce := compileEntry(Entry{Action: action, ICS: ICSPredicate{Protocol: "modbus", Addresses: specs}})
	return matchICSAddresses(&ce, EvalContext{ICS: ics})
}

// An address predicate on an ALLOW holds a message only when every span it
// touches lies inside the predicate; on a DENY or RESET it holds when any
// decoded span meets the predicate. Unknown spans never prove a match.
func TestICSAddressSpanSemantics(t *testing.T) {
	cases := []struct {
		name      string
		specs     []string
		ics       ICSContext
		allow     bool
		denyReset bool
	}{
		{"inside", []string{"10-11"}, ICSContext{Spans: []AddressSpan{span(10, 11)}}, true, true},
		{"subset", []string{"10-20"}, ICSContext{Spans: []AddressSpan{span(12, 14)}}, true, true},
		// The live escape: read or write at 11 for 8 against 10-11.
		{"partial overlap past the end", []string{"10-11"}, ICSContext{Spans: []AddressSpan{span(11, 18)}}, false, true},
		{"partial overlap before the start", []string{"10-11"}, ICSContext{Spans: []AddressSpan{span(5, 10)}}, false, true},
		{"covering the predicate", []string{"10-11"}, ICSContext{Spans: []AddressSpan{span(0, 100)}}, false, true},
		{"outside", []string{"10-11"}, ICSContext{Spans: []AddressSpan{span(12, 19)}}, false, false},
		{"adjacent entries together", []string{"10-11", "12-13"}, ICSContext{Spans: []AddressSpan{span(10, 13)}}, true, true},
		{"overlapping entries together", []string{"20-30", "10-25"}, ICSContext{Spans: []AddressSpan{span(10, 30)}}, true, true},
		{"gap between entries", []string{"10-11", "13-14"}, ICSContext{Spans: []AddressSpan{span(10, 14)}}, false, true},
		// FC 23 touches a read span and a write span.
		{"two spans inside", []string{"0-9", "100-109"}, ICSContext{Spans: []AddressSpan{span(0, 3), span(100, 101)}}, true, true},
		{"write span outside", []string{"0-9"}, ICSContext{Spans: []AddressSpan{span(0, 3), span(100, 101)}}, false, true},
		{"read span outside", []string{"100-109"}, ICSContext{Spans: []AddressSpan{span(0, 3), span(100, 101)}}, false, true},
		{"both spans outside", []string{"50-60"}, ICSContext{Spans: []AddressSpan{span(0, 3), span(100, 101)}}, false, false},
		// FC 5/6/22 touch one address.
		{"single inside", []string{"10-11"}, ICSContext{Spans: []AddressSpan{span(11, 11)}}, true, true},
		{"single outside", []string{"10-11"}, ICSContext{Spans: []AddressSpan{span(12, 12)}}, false, false},
		// Diagnostics, device identification and read replies touch no address.
		{"no address", []string{"0-65535"}, ICSContext{}, false, false},
		// Unknown function code or malformed PDU.
		{"unknown", []string{"10-11"}, ICSContext{SpansUnknown: true}, false, false},
		{"unknown with spans", []string{"0-65535"}, ICSContext{SpansUnknown: true, Spans: []AddressSpan{span(1, 1)}}, false, true},
		{"top of the address space", []string{"0xFFFFFFF0-0xFFFFFFFF"}, ICSContext{Spans: []AddressSpan{span(0xFFFFFFFE, 0xFFFFFFFF)}}, true, true},
	}
	for _, tc := range cases {
		if got := addressMatch(ActionAllow, tc.specs, &tc.ics); got != tc.allow {
			t.Errorf("%s: ALLOW matched=%v, want %v", tc.name, got, tc.allow)
		}
		for _, action := range []Action{ActionDeny, ActionReset} {
			if got := addressMatch(action, tc.specs, &tc.ics); got != tc.denyReset {
				t.Errorf("%s: %s matched=%v, want %v", tc.name, action, got, tc.denyReset)
			}
		}
		// Non-deciding actions bound their effect like an ALLOW.
		for _, action := range []Action{ActionRateLimit, ActionTag} {
			if got := addressMatch(action, tc.specs, &tc.ics); got != tc.allow {
				t.Errorf("%s: %s matched=%v, want %v", tc.name, action, got, tc.allow)
			}
		}
	}
}

// End to end through the evaluator: a range-crossing read is not admitted by
// an ALLOW of its start address and is denied by a DENY of its tail.
func TestEvaluatorRangeCrossingRead(t *testing.T) {
	unit := uint8(1)
	read := func(first, last uint32) EvalContext {
		return EvalContext{ICS: &ICSContext{Protocol: "modbus", HasFunctionCode: true, FunctionCode: 3, UnitID: &unit, Direction: "request",
			Spans: []AddressSpan{span(first, last)}}}
	}
	allow := NewEvaluator(&Snapshot{Default: ActionDeny, Firewall: []Entry{{
		ID: "allow", ICS: ICSPredicate{Protocol: "modbus", FunctionCode: []uint8{3}, UnitID: &unit, Addresses: []string{"10-11"}}, Action: ActionAllow,
	}}})
	if got := allow.Evaluate(read(10, 11)); got != ActionAllow {
		t.Fatalf("in-range read = %s", got)
	}
	if got := allow.Evaluate(read(11, 18)); got != ActionDeny {
		t.Fatalf("range-crossing read = %s, want DENY", got)
	}

	deny := NewEvaluator(&Snapshot{Default: ActionAllow, Firewall: []Entry{{
		ID: "deny", ICS: ICSPredicate{Protocol: "modbus", Addresses: []string{"100-199"}}, Action: ActionDeny,
	}}})
	if got := deny.Evaluate(read(90, 100)); got != ActionDeny {
		t.Fatalf("read reaching into the denied range = %s, want DENY", got)
	}
	if got := deny.Evaluate(read(90, 99)); got != ActionAllow {
		t.Fatalf("read below the denied range = %s, want ALLOW", got)
	}
	unknown := EvalContext{ICS: &ICSContext{Protocol: "modbus", HasFunctionCode: true, FunctionCode: 0x41, SpansUnknown: true}}
	if got := deny.Evaluate(unknown); got != ActionAllow {
		t.Fatalf("absent addresses = %s, want default ALLOW", got)
	}
}
