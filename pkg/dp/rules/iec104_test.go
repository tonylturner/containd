// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

package rules

import "testing"

func TestICSPredicateEmptyCountsIEC104Fields(t *testing.T) {
	cases := map[string]ICSPredicate{
		"typeIds": {TypeIDs: []int{46}},
		"classes": {Classes: []string{"control"}},
		"ca":      {CA: []uint16{1}},
		"ioa":     {IOA: []IOARange{{Start: 1, End: 2}}},
	}
	for name, pred := range cases {
		if icsPredicateEmpty(pred) {
			t.Fatalf("%s: predicate with only %s must not be empty", name, name)
		}
	}
	if !icsPredicateEmpty(ICSPredicate{}) {
		t.Fatal("zero predicate must be empty")
	}
}

func TestIEC104StubsNeverMatch(t *testing.T) {
	ca := uint16(1)
	typeID := uint8(46)
	ctx := EvalContext{
		Proto: "tcp",
		Port:  "2404",
		ICS: &ICSContext{
			Protocol:  "iec104",
			Direction: "request",
			IEC104:    &IEC104Context{APCIType: "I", TypeID: &typeID, CA: &ca, Class: "control"},
		},
	}
	ev := NewEvaluator(&Snapshot{
		Default: ActionAllow,
		Firewall: []Entry{{
			ID:     "iec-allow",
			ICS:    ICSPredicate{Protocol: "iec104", TypeIDs: []int{46}, CA: []uint16{1}, Mode: "enforce"},
			Action: ActionAllow,
		}},
	})
	if matched, mode := ev.IEC104Envelope(ctx, "enforce"); matched || mode != "" {
		t.Fatalf("IEC104Envelope = %v, %q; want false, \"\"", matched, mode)
	}
	if action, entry := ev.EvaluateIEC104(ctx); action != ActionDeny || entry != nil {
		t.Fatalf("EvaluateIEC104 = %s, %v; want DENY, nil", action, entry)
	}
}
