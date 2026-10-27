// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

package learn

import (
	"testing"
	"time"

	"github.com/tonylturner/containd/pkg/dp/dpi"
)

func TestRecordEventCreatesProfile(t *testing.T) {
	l := New()
	ev := dpi.Event{
		Proto:     "modbus",
		Kind:      "request",
		Timestamp: time.Now().UTC(),
		Attributes: map[string]any{
			"function_code": uint8(3),
			"unit_id":       uint8(1),
			"address":       uint16(40001),
			"quantity":      uint16(1),
			"is_write":      false,
		},
	}
	l.RecordEvent("192.168.1.10", "192.168.1.20", ev)

	profiles := l.Profiles()
	if len(profiles) != 1 {
		t.Fatalf("expected 1 profile, got %d", len(profiles))
	}
	p := profiles[0]
	if p.Protocol != "modbus" {
		t.Errorf("expected protocol modbus, got %s", p.Protocol)
	}
	if p.SourceIP != "192.168.1.10" {
		t.Errorf("expected source 192.168.1.10, got %s", p.SourceIP)
	}
	if p.DestIP != "192.168.1.20" {
		t.Errorf("expected dest 192.168.1.20, got %s", p.DestIP)
	}
	if !p.FunctionCodes[3] {
		t.Error("expected function code 3 to be recorded")
	}
	if !p.UnitIDs[1] {
		t.Error("expected unit ID 1 to be recorded")
	}
	if !p.Addresses["40001"] {
		t.Error("expected address 40001 to be recorded")
	}
	if p.PacketCount != 1 {
		t.Errorf("expected packet count 1, got %d", p.PacketCount)
	}
	if !p.ReadSeen {
		t.Error("expected ReadSeen to be true for is_write=false")
	}
	if p.WriteSeen {
		t.Error("expected WriteSeen to be false")
	}
}

func TestMultipleEventsSamePairMerge(t *testing.T) {
	l := New()
	now := time.Now().UTC()

	ev1 := dpi.Event{
		Proto:     "modbus",
		Kind:      "request",
		Timestamp: now,
		Attributes: map[string]any{
			"function_code": uint8(3),
			"unit_id":       uint8(1),
			"address":       uint16(40001),
			"quantity":      uint16(1),
			"is_write":      false,
		},
	}
	ev2 := dpi.Event{
		Proto:     "modbus",
		Kind:      "request",
		Timestamp: now.Add(time.Second),
		Attributes: map[string]any{
			"function_code": uint8(16),
			"unit_id":       uint8(1),
			"address":       uint16(40002),
			"quantity":      uint16(1),
			"byte_count":    uint8(2),
			"is_write":      true,
		},
	}
	ev3 := dpi.Event{
		Proto:     "modbus",
		Kind:      "request",
		Timestamp: now.Add(2 * time.Second),
		Attributes: map[string]any{
			"function_code": uint8(3),
			"unit_id":       uint8(2),
			"address":       uint16(40001),
			"quantity":      uint16(1),
			"is_write":      false,
		},
	}

	l.RecordEvent("192.168.1.10", "192.168.1.20", ev1)
	l.RecordEvent("192.168.1.10", "192.168.1.20", ev2)
	l.RecordEvent("192.168.1.10", "192.168.1.20", ev3)

	profiles := l.Profiles()
	if len(profiles) != 1 {
		t.Fatalf("expected 1 profile (same pair), got %d", len(profiles))
	}
	p := profiles[0]
	if p.PacketCount != 3 {
		t.Errorf("expected packet count 3, got %d", p.PacketCount)
	}
	if !p.FunctionCodes[3] || !p.FunctionCodes[16] {
		t.Error("expected function codes 3 and 16")
	}
	if !p.UnitIDs[1] || !p.UnitIDs[2] {
		t.Error("expected unit IDs 1 and 2")
	}
	if !p.Addresses["40001"] || !p.Addresses["40002"] {
		t.Error("expected addresses 40001 and 40002")
	}
	if !p.ReadSeen {
		t.Error("expected ReadSeen")
	}
	if !p.WriteSeen {
		t.Error("expected WriteSeen")
	}

	generated := l.GenerateRules()
	if len(generated) != 3 {
		t.Fatalf("expected one rule per unit/function tuple, got %d: %+v", len(generated), generated)
	}
	want := map[string]struct {
		unit uint8
		fc   uint8
		addr string
	}{
		"learned-modbus-192.168.1.10-192.168.1.20-u1-fc03": {unit: 1, fc: 3, addr: "40001"},
		"learned-modbus-192.168.1.10-192.168.1.20-u1-fc10": {unit: 1, fc: 16, addr: "40002"},
		"learned-modbus-192.168.1.10-192.168.1.20-u2-fc03": {unit: 2, fc: 3, addr: "40001"},
	}
	for _, rule := range generated {
		expected, ok := want[rule.ID]
		if !ok {
			t.Errorf("unexpected rule ID %q", rule.ID)
			continue
		}
		if rule.ICS.UnitID == nil || *rule.ICS.UnitID != expected.unit {
			t.Errorf("%s unit ID = %v, want %d", rule.ID, rule.ICS.UnitID, expected.unit)
		}
		if len(rule.ICS.FunctionCode) != 1 || rule.ICS.FunctionCode[0] != expected.fc {
			t.Errorf("%s function codes = %v, want %d", rule.ID, rule.ICS.FunctionCode, expected.fc)
		}
		if len(rule.ICS.Addresses) != 1 || rule.ICS.Addresses[0] != expected.addr {
			t.Errorf("%s addresses = %v, want only %s", rule.ID, rule.ICS.Addresses, expected.addr)
		}
		delete(want, rule.ID)
	}
	if len(want) != 0 {
		t.Errorf("missing rules for tuples: %v", want)
	}
}

func TestGenerateRulesProducesValidRules(t *testing.T) {
	l := New()
	now := time.Now().UTC()

	ev := dpi.Event{
		Proto:     "modbus",
		Kind:      "request",
		Timestamp: now,
		Attributes: map[string]any{
			"function_code": uint8(3),
			"unit_id":       uint8(1),
			"address":       uint16(40001),
			"quantity":      uint16(1),
			"is_write":      false,
		},
	}
	l.RecordEvent("192.168.1.10", "192.168.1.20", ev)

	rules := l.GenerateRules()
	if len(rules) != 1 {
		t.Fatalf("expected 1 rule, got %d", len(rules))
	}
	r := rules[0]
	if r.ID != "learned-modbus-192.168.1.10-192.168.1.20-u1-fc03" {
		t.Errorf("unexpected rule ID: %s", r.ID)
	}
	if r.Action != "ALLOW" {
		t.Errorf("expected ALLOW action, got %s", string(r.Action))
	}
	if r.ICS.Protocol != "modbus" {
		t.Errorf("expected modbus protocol, got %s", r.ICS.Protocol)
	}
	if r.ICS.Mode != "" {
		t.Errorf("expected inherited (empty) mode, got %s", r.ICS.Mode)
	}
	if len(r.ICS.FunctionCode) != 1 || r.ICS.FunctionCode[0] != 3 {
		t.Errorf("unexpected function codes: %v", r.ICS.FunctionCode)
	}
	if len(r.Sources) != 1 || r.Sources[0] != "192.168.1.10/32" {
		t.Errorf("unexpected sources: %v", r.Sources)
	}
	if len(r.Destinations) != 1 || r.Destinations[0] != "192.168.1.20/32" {
		t.Errorf("unexpected destinations: %v", r.Destinations)
	}
	if r.ICS.UnitID == nil || *r.ICS.UnitID != 1 {
		t.Error("expected UnitID to be 1")
	}
}

func TestReadOnlyClassification(t *testing.T) {
	l := New()
	ev := dpi.Event{
		Proto:     "modbus",
		Kind:      "request",
		Timestamp: time.Now().UTC(),
		Attributes: map[string]any{
			"function_code": uint8(3),
			"unit_id":       uint8(1),
			"address":       uint16(10),
			"quantity":      uint16(1),
			"is_write":      false,
		},
	}
	l.RecordEvent("10.0.0.1", "10.0.0.2", ev)

	rules := l.GenerateRules()
	if len(rules) != 1 {
		t.Fatal("expected 1 rule")
	}
	if !rules[0].ICS.ReadOnly {
		t.Error("expected ReadOnly to be true for read-only traffic")
	}
	if rules[0].ICS.WriteOnly {
		t.Error("expected WriteOnly to be false for read-only traffic")
	}
}

func TestWriteOnlyClassification(t *testing.T) {
	l := New()
	ev := dpi.Event{
		Proto:     "modbus",
		Kind:      "request",
		Timestamp: time.Now().UTC(),
		Attributes: map[string]any{
			"function_code": uint8(6),
			"unit_id":       uint8(1),
			"address":       uint16(10),
			"is_write":      true,
		},
	}
	l.RecordEvent("10.0.0.1", "10.0.0.2", ev)

	rules := l.GenerateRules()
	if len(rules) != 1 {
		t.Fatal("expected 1 rule")
	}
	if rules[0].ICS.ReadOnly {
		t.Error("expected ReadOnly to be false for write-only traffic")
	}
	if !rules[0].ICS.WriteOnly {
		t.Error("expected WriteOnly to be true for write-only traffic")
	}
}

func TestMixedReadWriteClassification(t *testing.T) {
	l := New()
	now := time.Now().UTC()

	l.RecordEvent("10.0.0.1", "10.0.0.2", dpi.Event{
		Proto:     "modbus",
		Kind:      "request",
		Timestamp: now,
		Attributes: map[string]any{
			"function_code": uint8(6),
			"unit_id":       uint8(1),
			"address":       uint16(10),
			"is_write":      false,
		},
	})
	l.RecordEvent("10.0.0.1", "10.0.0.2", dpi.Event{
		Proto:     "modbus",
		Kind:      "request",
		Timestamp: now.Add(time.Second),
		Attributes: map[string]any{
			"function_code": uint8(6),
			"unit_id":       uint8(1),
			"address":       uint16(10),
			"is_write":      true,
		},
	})

	rules := l.GenerateRules()
	if len(rules) != 1 {
		t.Fatal("expected 1 rule")
	}
	if rules[0].ICS.ReadOnly {
		t.Error("expected ReadOnly false for mixed traffic")
	}
	if rules[0].ICS.WriteOnly {
		t.Error("expected WriteOnly false for mixed traffic")
	}
}

func TestClearResetsProfiles(t *testing.T) {
	l := New()
	l.RecordEvent("10.0.0.1", "10.0.0.2", dpi.Event{
		Proto: "modbus", Kind: "request", Timestamp: time.Now().UTC(),
		Attributes: map[string]any{"function_code": uint8(6), "unit_id": uint8(1), "address": uint16(0)},
	})
	if len(l.Profiles()) == 0 {
		t.Fatal("expected profiles before clear")
	}
	l.Clear()
	if len(l.Profiles()) != 0 {
		t.Error("expected no profiles after clear")
	}
}

func TestDifferentPairsCreateSeparateProfiles(t *testing.T) {
	l := New()
	now := time.Now().UTC()

	l.RecordEvent("10.0.0.1", "10.0.0.2", dpi.Event{
		Proto: "modbus", Kind: "request", Timestamp: now,
		Attributes: map[string]any{"function_code": uint8(6), "unit_id": uint8(1), "address": uint16(0)},
	})
	l.RecordEvent("10.0.0.3", "10.0.0.4", dpi.Event{
		Proto: "modbus", Kind: "request", Timestamp: now,
		Attributes: map[string]any{"function_code": uint8(6), "unit_id": uint8(1), "address": uint16(0)},
	})

	profiles := l.Profiles()
	if len(profiles) != 2 {
		t.Fatalf("expected 2 profiles, got %d", len(profiles))
	}
}
