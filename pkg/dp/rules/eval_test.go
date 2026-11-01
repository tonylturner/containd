// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

package rules

import (
	"net"
	"testing"
	"time"
)

func TestEvaluatorMatch(t *testing.T) {
	snap := Snapshot{DPIMode: "enforce",
		Default: ActionDeny,
		Firewall: []Entry{
			{
				ID:           "1",
				SourceZones:  []string{"it"},
				DestZones:    []string{"dmz"},
				Sources:      []string{"192.168.1.0/24"},
				Destinations: []string{"10.0.0.0/24"},
				Protocols:    []Protocol{{Name: "tcp", Port: "80"}},
				Action:       ActionAllow,
			},
		},
	}
	ev := NewEvaluator(&snap)
	ctx := EvalContext{
		SrcZone: "it",
		DstZone: "dmz",
		SrcIP:   net.ParseIP("192.168.1.10"),
		DstIP:   net.ParseIP("10.0.0.5"),
		Proto:   "tcp",
		Port:    "80",
	}
	if got := ev.Evaluate(ctx); got != ActionAllow {
		t.Fatalf("expected allow, got %s", got)
	}
}

func TestEvaluatorDefaultAction(t *testing.T) {
	for _, tc := range []struct {
		def, want Action
	}{
		{ActionAllow, ActionAllow},
		{ActionDeny, ActionDeny},
		{"", ActionDeny},
		{"REJECT", ActionDeny},
	} {
		if got := NewEvaluator(&Snapshot{DPIMode: "enforce", Default: tc.def}).Evaluate(EvalContext{}); got != tc.want {
			t.Fatalf("default %q evaluated to %s, want %s", tc.def, got, tc.want)
		}
	}
}

func TestPortRange(t *testing.T) {
	snap := Snapshot{DPIMode: "enforce",
		Default: ActionDeny,
		Firewall: []Entry{
			{
				ID:        "1",
				Protocols: []Protocol{{Name: "tcp", Port: "1000-2000"}},
				Action:    ActionAllow,
			},
		},
	}
	ev := NewEvaluator(&snap)
	ctx := EvalContext{Proto: "tcp", Port: "1500"}
	if got := ev.Evaluate(ctx); got != ActionAllow {
		t.Fatalf("expected allow, got %s", got)
	}
	ctx.Port = "80"
	if got := ev.Evaluate(ctx); got != ActionDeny {
		t.Fatalf("expected deny, got %s", got)
	}
}

func TestIdentityMatch(t *testing.T) {
	snap := Snapshot{DPIMode: "enforce",
		Default: ActionDeny,
		Firewall: []Entry{
			{
				ID:         "1",
				Identities: []string{"operator"},
				Action:     ActionAllow,
			},
		},
	}
	ev := NewEvaluator(&snap)
	ctx := EvalContext{Identities: []string{"operator"}}
	if got := ev.Evaluate(ctx); got != ActionAllow {
		t.Fatalf("expected allow, got %s", got)
	}
	ctx.Identities = []string{"guest"}
	if got := ev.Evaluate(ctx); got != ActionDeny {
		t.Fatalf("expected deny, got %s", got)
	}
}

func TestICSMatch(t *testing.T) {
	unit := uint8(1)
	snap := Snapshot{DPIMode: "enforce",
		Default: ActionDeny,
		Firewall: []Entry{
			{
				ID: "1",
				ICS: ICSPredicate{
					Protocol:     "modbus",
					FunctionCode: []uint8{3, 16},
					UnitID:       &unit,
				},
				Action: ActionAllow,
			},
		},
	}
	ev := NewEvaluator(&snap)
	ctx := EvalContext{
		ICS: &ICSContext{
			Protocol:        "modbus",
			HasFunctionCode: true,
			FunctionCode:    3,
			UnitID:          &unit,
		},
	}
	if got := ev.Evaluate(ctx); got != ActionAllow {
		t.Fatalf("expected allow, got %s", got)
	}
	ctx.ICS.FunctionCode = 5
	if got := ev.Evaluate(ctx); got != ActionDeny {
		t.Fatalf("expected deny, got %s", got)
	}
}

// matchAddress reports whether an ALLOW with the specifications matches a
// message touching the single address addr.
func matchAddress(specs []string, addr uint32) bool {
	return allowMatches(specs, AddressSpan{Low: addr, High: addr})
}

func TestMatchAddressSingleDecimal(t *testing.T) {
	if !matchAddress([]string{"256"}, 256) {
		t.Fatal("expected decimal single address to match")
	}
	if matchAddress([]string{"256"}, 257) {
		t.Fatal("expected decimal single address not to match different value")
	}
}

func TestMatchAddressSingleHex(t *testing.T) {
	// 0x0100 == 256
	if !matchAddress([]string{"0x0100"}, 0x0100) {
		t.Fatal("expected hex single address to match")
	}
	if !matchAddress([]string{"0x0100"}, 256) {
		t.Fatal("expected hex entry to match decimal context with same value")
	}
	if matchAddress([]string{"0x0100"}, 0x0101) {
		t.Fatal("expected hex single address not to match different value")
	}
}

func TestMatchAddressRangeHex(t *testing.T) {
	// 0x0150 (=336) is within 0x0100-0x01FF (=256-511)
	if !matchAddress([]string{"0x0100-0x01FF"}, 0x0150) {
		t.Fatal("expected address within hex range to match")
	}
	// 0x0200 (=512) is outside 0x0100-0x01FF
	if matchAddress([]string{"0x0100-0x01FF"}, 0x0200) {
		t.Fatal("expected address outside hex range not to match")
	}
}

func TestMatchAddressRangeDecimal(t *testing.T) {
	if !matchAddress([]string{"100-511"}, 300) {
		t.Fatal("expected address within decimal range to match")
	}
	if matchAddress([]string{"100-511"}, 512) {
		t.Fatal("expected address outside decimal range not to match")
	}
}

func TestMatchAddressMixedFormat(t *testing.T) {
	// Hex range, decimal context: 336 is within 0x0100-0x01FF (256-511)
	if !matchAddress([]string{"0x0100-0x01FF"}, 336) {
		t.Fatal("expected decimal context addr within hex range to match")
	}
	// Decimal range, hex context: 0x012C (=300) is within 100-511
	if !matchAddress([]string{"100-511"}, 0x012C) {
		t.Fatal("expected hex context addr within decimal range to match")
	}
}

func TestICSAddressRangeEval(t *testing.T) {
	unit := uint8(1)
	snap := Snapshot{DPIMode: "enforce",
		Default: ActionDeny,
		Firewall: []Entry{
			{
				ID: "addr-range",
				ICS: ICSPredicate{
					Protocol:     "modbus",
					FunctionCode: []uint8{3},
					UnitID:       &unit,
					Addresses:    []string{"0x0100-0x01FF"},
				},
				Action: ActionAllow,
			},
		},
	}
	ev := NewEvaluator(&snap)
	ctx := EvalContext{
		ICS: &ICSContext{
			Protocol:        "modbus",
			HasFunctionCode: true,
			FunctionCode:    3,
			UnitID:          &unit,
			Spans:           []AddressSpan{{Low: 0x0150, High: 0x0150}},
		},
	}
	if got := ev.Evaluate(ctx); got != ActionAllow {
		t.Fatalf("expected allow for address in range, got %s", got)
	}
	ctx.ICS.Spans = []AddressSpan{{Low: 0x0200, High: 0x0200}}
	if got := ev.Evaluate(ctx); got != ActionDeny {
		t.Fatalf("expected deny for address out of range, got %s", got)
	}
}

func TestScheduleMatchWithinWindow(t *testing.T) {
	// Wednesday 10:00 UTC should match a Mon-Fri 09:00-17:00 schedule.
	snap := Snapshot{DPIMode: "enforce",
		Default: ActionDeny,
		Firewall: []Entry{
			{
				ID:     "sched-1",
				Action: ActionAllow,
				Schedule: SchedulePredicate{
					DaysOfWeek: []string{"Monday", "Tuesday", "Wednesday", "Thursday", "Friday"},
					StartTime:  "09:00",
					EndTime:    "17:00",
					Timezone:   "UTC",
				},
			},
		},
	}
	ev := NewEvaluator(&snap)
	// 2025-01-08 is a Wednesday.
	ctx := EvalContext{
		Now: time.Date(2025, 1, 8, 10, 0, 0, 0, time.UTC),
	}
	if got := ev.Evaluate(ctx); got != ActionAllow {
		t.Fatalf("expected allow within schedule, got %s", got)
	}
}

func TestScheduleNoMatchOutsideWindow(t *testing.T) {
	// Wednesday 20:00 UTC is outside 09:00-17:00.
	snap := Snapshot{DPIMode: "enforce",
		Default: ActionDeny,
		Firewall: []Entry{
			{
				ID:     "sched-2",
				Action: ActionAllow,
				Schedule: SchedulePredicate{
					DaysOfWeek: []string{"Monday", "Tuesday", "Wednesday", "Thursday", "Friday"},
					StartTime:  "09:00",
					EndTime:    "17:00",
					Timezone:   "UTC",
				},
			},
		},
	}
	ev := NewEvaluator(&snap)
	ctx := EvalContext{
		Now: time.Date(2025, 1, 8, 20, 0, 0, 0, time.UTC),
	}
	if got := ev.Evaluate(ctx); got != ActionDeny {
		t.Fatalf("expected deny outside time window, got %s", got)
	}
}

func TestScheduleDayOfWeekFilter(t *testing.T) {
	// Saturday should not match a Mon-Fri schedule even if time is within range.
	snap := Snapshot{DPIMode: "enforce",
		Default: ActionDeny,
		Firewall: []Entry{
			{
				ID:     "sched-3",
				Action: ActionAllow,
				Schedule: SchedulePredicate{
					DaysOfWeek: []string{"Monday", "Tuesday", "Wednesday", "Thursday", "Friday"},
					StartTime:  "09:00",
					EndTime:    "17:00",
					Timezone:   "UTC",
				},
			},
		},
	}
	ev := NewEvaluator(&snap)
	// 2025-01-11 is a Saturday.
	ctx := EvalContext{
		Now: time.Date(2025, 1, 11, 10, 0, 0, 0, time.UTC),
	}
	if got := ev.Evaluate(ctx); got != ActionDeny {
		t.Fatalf("expected deny on Saturday (weekday filter), got %s", got)
	}
}

func TestScheduleTimezoneConversion(t *testing.T) {
	// Rule is for America/New_York 09:00-17:00. At 14:00 UTC that's 09:00 EST => should match.
	snap := Snapshot{DPIMode: "enforce",
		Default: ActionDeny,
		Firewall: []Entry{
			{
				ID:     "sched-tz",
				Action: ActionAllow,
				Schedule: SchedulePredicate{
					DaysOfWeek: []string{"Wednesday"},
					StartTime:  "09:00",
					EndTime:    "17:00",
					Timezone:   "America/New_York",
				},
			},
		},
	}
	ev := NewEvaluator(&snap)
	// 2025-01-08 14:00 UTC = 09:00 EST (Wednesday).
	ctx := EvalContext{
		Now: time.Date(2025, 1, 8, 14, 0, 0, 0, time.UTC),
	}
	if got := ev.Evaluate(ctx); got != ActionAllow {
		t.Fatalf("expected allow with timezone conversion, got %s", got)
	}
	// 2025-01-08 12:00 UTC = 07:00 EST => outside window.
	ctx.Now = time.Date(2025, 1, 8, 12, 0, 0, 0, time.UTC)
	if got := ev.Evaluate(ctx); got != ActionDeny {
		t.Fatalf("expected deny before schedule in EST, got %s", got)
	}
}

func TestScheduleNoScheduleAlwaysMatches(t *testing.T) {
	// A rule without a schedule should always match regardless of time.
	snap := Snapshot{DPIMode: "enforce",
		Default: ActionDeny,
		Firewall: []Entry{
			{
				ID:     "no-sched",
				Action: ActionAllow,
			},
		},
	}
	ev := NewEvaluator(&snap)
	ctx := EvalContext{
		Now: time.Date(2025, 1, 11, 3, 0, 0, 0, time.UTC),
	}
	if got := ev.Evaluate(ctx); got != ActionAllow {
		t.Fatalf("expected allow with no schedule, got %s", got)
	}
}

// TestUnparseableICSAddressesMatchNothing checks that an address predicate
// with an entry that fails to parse matches no address, as a CIDR side that
// lists only unparseable networks matches no host: it must neither widen an
// ALLOW to every address nor narrow it to the entries that parse.
func TestUnparseableICSAddressesMatchNothing(t *testing.T) {
	for _, specs := range [][]string{{"junk", "1-"}, {"5", "0x01G0"}, {"0-0x200", "0x200-0x100"}} {
		ev := NewEvaluator(&Snapshot{DPIMode: "enforce", Default: ActionDeny, Firewall: []Entry{{
			ID:     "write-one",
			ICS:    ICSPredicate{Protocol: "modbus", Addresses: specs},
			Action: ActionAllow,
		}}})
		for _, addr := range []uint32{5, 0x0100} {
			ctx := EvalContext{ICS: &ICSContext{Protocol: "modbus", Spans: []AddressSpan{{Low: addr, High: addr}}}}
			if got := ev.Evaluate(ctx); got != ActionDeny {
				t.Fatalf("addresses %q at %d = %s, want DENY", specs, addr, got)
			}
		}
	}
	if matchAddress([]string{"junk"}, 5) {
		t.Fatal("an unparseable specification matched")
	}
}
