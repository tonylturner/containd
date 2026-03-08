// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

package signatures

import (
	"strings"
	"testing"
	"time"

	"github.com/tonylturner/containd/pkg/dp/dpi"
)

func TestLoadBuiltins(t *testing.T) {
	e := New()
	e.LoadBuiltins()
	sigs := e.List()
	if len(sigs) == 0 {
		t.Fatal("expected builtin signatures to be loaded")
	}
	// Verify a few known IDs exist.
	ids := map[string]bool{}
	for _, s := range sigs {
		ids[s.ID] = true
	}
	for _, want := range []string{"MODBUS-SCAN-001", "DNP3-COLD-RESTART", "CIP-RESET-001", "S7-PLC-STOP", "ICS-WRITE-STORM"} {
		if !ids[want] {
			t.Errorf("missing builtin signature %s", want)
		}
	}
}

func TestMatchModbusWriteCoilAll(t *testing.T) {
	e := New()
	e.LoadBuiltins()

	ev := dpi.Event{
		Proto:     "modbus",
		Kind:      "request",
		Timestamp: time.Now(),
		Attributes: map[string]any{
			"function_code": uint8(15),
			"quantity":      uint16(2000),
			"is_write":      true,
		},
	}
	matches := e.Match(ev)
	found := false
	for _, m := range matches {
		if m.Signature.ID == "MODBUS-WRITE-COIL-ALL" {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected MODBUS-WRITE-COIL-ALL to match; got %d matches", len(matches))
	}
}

func TestNoMatchForReadEvents(t *testing.T) {
	e := New()
	e.LoadBuiltins()

	// A simple Modbus read event should not trigger write-related signatures.
	ev := dpi.Event{
		Proto:     "modbus",
		Kind:      "request",
		Timestamp: time.Now(),
		Attributes: map[string]any{
			"function_code": uint8(3), // Read Holding Registers
			"is_write":      false,
		},
	}
	matches := e.Match(ev)
	for _, m := range matches {
		// ICS-WRITE-STORM requires is_write=true so it should not match.
		if m.Signature.ID == "ICS-WRITE-STORM" {
			t.Errorf("ICS-WRITE-STORM should not match a read event")
		}
		if m.Signature.ID == "MODBUS-WRITE-COIL-ALL" {
			t.Errorf("MODBUS-WRITE-COIL-ALL should not match a read event")
		}
	}
}

func TestCustomSignatureLoadFromJSON(t *testing.T) {
	e := New()

	jsonData := `[
		{
			"id": "CUSTOM-001",
			"name": "Custom Modbus Write",
			"protocol": "modbus",
			"severity": "high",
			"conditions": [
				{"field": "function_code", "op": "in", "value": [5, 6, 15, 16]}
			]
		}
	]`

	if err := e.LoadFromJSON(strings.NewReader(jsonData)); err != nil {
		t.Fatalf("LoadFromJSON failed: %v", err)
	}

	sigs := e.List()
	if len(sigs) != 1 {
		t.Fatalf("expected 1 signature, got %d", len(sigs))
	}
	if sigs[0].ID != "CUSTOM-001" {
		t.Errorf("expected ID CUSTOM-001, got %s", sigs[0].ID)
	}

	// Test that it matches a write event.
	ev := dpi.Event{
		Proto:     "modbus",
		Kind:      "request",
		Timestamp: time.Now(),
		Attributes: map[string]any{
			"function_code": float64(5),
		},
	}
	matches := e.Match(ev)
	if len(matches) != 1 {
		t.Fatalf("expected 1 match, got %d", len(matches))
	}
	if matches[0].Signature.ID != "CUSTOM-001" {
		t.Errorf("expected CUSTOM-001 match, got %s", matches[0].Signature.ID)
	}
}

func TestConditionEquals(t *testing.T) {
	tests := []struct {
		name     string
		cond     Condition
		val      any
		expected bool
	}{
		{"int equals", Condition{Op: "equals", Value: float64(5)}, uint8(5), true},
		{"int not equals", Condition{Op: "equals", Value: float64(5)}, uint8(6), false},
		{"string equals", Condition{Op: "equals", Value: "modbus"}, "modbus", true},
		{"string not equals", Condition{Op: "equals", Value: "modbus"}, "dnp3", false},
		{"bool equals true", Condition{Op: "equals", Value: true}, true, true},
		{"bool equals false", Condition{Op: "equals", Value: true}, false, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := evalCondition(tt.cond, tt.val)
			if got != tt.expected {
				t.Errorf("evalCondition(%v, %v) = %v, want %v", tt.cond, tt.val, got, tt.expected)
			}
		})
	}
}

func TestConditionIn(t *testing.T) {
	cond := Condition{Op: "in", Value: []any{float64(5), float64(6), float64(15), float64(16)}}
	if !evalCondition(cond, uint8(5)) {
		t.Error("expected 5 to be in set")
	}
	if !evalCondition(cond, float64(16)) {
		t.Error("expected 16 to be in set")
	}
	if evalCondition(cond, uint8(3)) {
		t.Error("expected 3 to NOT be in set")
	}
}

func TestConditionGtLt(t *testing.T) {
	gtCond := Condition{Op: "gt", Value: float64(1000)}
	if !evalCondition(gtCond, uint16(2000)) {
		t.Error("expected 2000 > 1000")
	}
	if evalCondition(gtCond, uint16(500)) {
		t.Error("expected 500 NOT > 1000")
	}

	ltCond := Condition{Op: "lt", Value: float64(10)}
	if !evalCondition(ltCond, uint8(5)) {
		t.Error("expected 5 < 10")
	}
	if evalCondition(ltCond, uint8(15)) {
		t.Error("expected 15 NOT < 10")
	}
}

func TestConditionContainsAndRegex(t *testing.T) {
	containsCond := Condition{Op: "contains", Value: "cold"}
	if !evalCondition(containsCond, "cold_restart") {
		t.Error("expected 'cold_restart' to contain 'cold'")
	}

	regexCond := Condition{Op: "regex", Value: "^SIG-.*-001$"}
	if !evalCondition(regexCond, "SIG-TRITON-001") {
		t.Error("expected regex match")
	}
	if evalCondition(regexCond, "SIG-TRITON-002") {
		t.Error("expected no regex match")
	}
}

func TestRemoveSignature(t *testing.T) {
	e := New()
	e.Add(Signature{ID: "TEST-001", Name: "Test", Conditions: []Condition{{Field: "kind", Op: "equals", Value: "test"}}})
	e.Add(Signature{ID: "TEST-002", Name: "Test2", Conditions: []Condition{{Field: "kind", Op: "equals", Value: "test"}}})

	if !e.Remove("TEST-001") {
		t.Error("expected Remove to return true")
	}
	if len(e.List()) != 1 {
		t.Errorf("expected 1 signature after remove, got %d", len(e.List()))
	}
	if e.Remove("TEST-999") {
		t.Error("expected Remove to return false for non-existent ID")
	}
}

func TestMatchHistory(t *testing.T) {
	e := New()
	e.Add(Signature{
		ID:       "TEST-001",
		Name:     "Test",
		Protocol: "modbus",
		Conditions: []Condition{
			{Field: "function_code", Op: "equals", Value: float64(5)},
		},
	})

	ev := dpi.Event{
		Proto:     "modbus",
		Kind:      "request",
		Timestamp: time.Now(),
		Attributes: map[string]any{
			"function_code": uint8(5),
		},
	}
	e.Match(ev)

	history := e.Matches(10)
	if len(history) != 1 {
		t.Fatalf("expected 1 match in history, got %d", len(history))
	}
	if history[0].Signature.ID != "TEST-001" {
		t.Errorf("expected TEST-001 in history, got %s", history[0].Signature.ID)
	}
}

func TestLoadFromJSONErrors(t *testing.T) {
	e := New()

	// Missing ID
	err := e.LoadFromJSON(strings.NewReader(`[{"name":"no id","conditions":[{"field":"x","op":"equals","value":1}]}]`))
	if err == nil {
		t.Error("expected error for missing ID")
	}

	// No conditions
	err = e.LoadFromJSON(strings.NewReader(`[{"id":"X","name":"no conds","conditions":[]}]`))
	if err == nil {
		t.Error("expected error for empty conditions")
	}

	// Invalid JSON
	err = e.LoadFromJSON(strings.NewReader(`not json`))
	if err == nil {
		t.Error("expected error for invalid JSON")
	}
}
