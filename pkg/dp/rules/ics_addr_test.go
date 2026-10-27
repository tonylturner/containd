// SPDX-License-Identifier: Apache-2.0

package rules

import (
	"strings"
	"testing"
)

// acceptedICSAddresses are address entries ParseICSAddressSpec accepts,
// with the range they parse to.
var acceptedICSAddresses = []struct {
	spec      string
	low, high uint32
}{
	{"0", 0, 0},
	{"256", 256, 256},
	{"0010", 10, 10},
	{"0x0100", 256, 256},
	{"0X01ff", 511, 511},
	{"100-511", 100, 511},
	{"0x0100-0x01FF", 256, 511},
	{"0x0100-511", 256, 511},
	{"7-7", 7, 7},
	{" 0x0100 - 0x01FF ", 256, 511},
	{"65535", 65535, 65535},
	{"4294967295", 4294967295, 4294967295},
	{"0-0xFFFFFFFF", 0, 4294967295},
}

// refusedICSAddresses are address entries ParseICSAddressSpec refuses,
// with a fragment of the reason.
var refusedICSAddresses = []struct{ spec, reason string }{
	{"", "not a decimal or 0x hex value"},
	{"  ", "not a decimal or 0x hex value"},
	{"0x01G0", "not a decimal or 0x hex value"},
	{"junk", "not a decimal or 0x hex value"},
	{"0x", "not a decimal or 0x hex value"},
	{"0x0x10", "not a decimal or 0x hex value"},
	{"+5", "not a decimal or 0x hex value"},
	{"1_000", "not a decimal or 0x hex value"},
	{"1.5", "not a decimal or 0x hex value"},
	{"-5", "negative"},
	{" -5", "negative"},
	{"-0x10", "negative"},
	{"5-", "not a decimal or 0x hex value"},
	{"5--6", "not a decimal or 0x hex value"},
	{"1-2-3", "not a decimal or 0x hex value"},
	{"0x200-0x100", "range starts at 512 after its end 256"},
	{"10-9", "range starts at 10 after its end 9"},
	{"4294967296", "exceeds the largest address 4294967295"},
	{"0-0x100000000", "exceeds the largest address 4294967295"},
}

func TestParseICSAddressSpec(t *testing.T) {
	for _, tc := range acceptedICSAddresses {
		low, high, err := ParseICSAddressSpec(tc.spec)
		if err != nil || low != tc.low || high != tc.high {
			t.Errorf("ParseICSAddressSpec(%q) = %d, %d, %v; want %d, %d", tc.spec, low, high, err, tc.low, tc.high)
		}
	}
	for _, tc := range refusedICSAddresses {
		if low, high, err := ParseICSAddressSpec(tc.spec); err == nil || !strings.Contains(err.Error(), tc.reason) {
			t.Errorf("ParseICSAddressSpec(%q) = %d, %d, %v; want an error with %q", tc.spec, low, high, err, tc.reason)
		}
	}
}

func TestICSAddressMax(t *testing.T) {
	if got := ICSAddressMax("modbus"); got != 65535 {
		t.Errorf("modbus maximum = %d", got)
	}
	for _, proto := range []string{"dnp3", "cip"} {
		if got := ICSAddressMax(proto); got != MaxICSAddress {
			t.Errorf("%s maximum = %d", proto, got)
		}
	}
}

// The evaluator matches every accepted entry on exactly its range.
func TestEvaluatorMatchesAcceptedICSAddresses(t *testing.T) {
	for _, tc := range acceptedICSAddresses {
		ev := NewEvaluator(&Snapshot{Default: ActionDeny, Firewall: []Entry{{
			ID: "addr", ICS: ICSPredicate{Protocol: "modbus", Addresses: []string{tc.spec}}, Action: ActionAllow,
		}}})
		decide := func(addr uint32) Action {
			return ev.Evaluate(EvalContext{ICS: &ICSContext{Protocol: "modbus", Spans: []AddressSpan{{Low: addr, High: addr}}}})
		}
		if decide(tc.low) != ActionAllow || decide(tc.high) != ActionAllow {
			t.Errorf("%q does not match its ends %d, %d", tc.spec, tc.low, tc.high)
		}
		if tc.low > 0 && decide(tc.low-1) != ActionDeny {
			t.Errorf("%q matches %d", tc.spec, tc.low-1)
		}
		if tc.high < MaxICSAddress && decide(tc.high+1) != ActionDeny {
			t.Errorf("%q matches %d", tc.spec, tc.high+1)
		}
	}
}

// A refused entry makes the whole address predicate match nothing, even
// next to a valid entry that holds the address: it never silently narrows
// to the entries that parse.
func TestEvaluatorRefusedICSAddressMatchesNothing(t *testing.T) {
	for _, tc := range refusedICSAddresses {
		ev := NewEvaluator(&Snapshot{Default: ActionDeny, Firewall: []Entry{{
			ID: "addr", ICS: ICSPredicate{Protocol: "modbus", Addresses: []string{"0-65535", tc.spec}}, Action: ActionAllow,
		}}})
		for _, addr := range []uint32{0, 5, 256, 512} {
			if got := ev.Evaluate(EvalContext{ICS: &ICSContext{Protocol: "modbus", Spans: []AddressSpan{{Low: addr, High: addr}}}}); got != ActionDeny {
				t.Errorf("addresses [0-65535 %q] at %d = %s, want DENY", tc.spec, addr, got)
			}
		}
	}
}
