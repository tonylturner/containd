// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

package signatures

import (
	"testing"

	"github.com/tonylturner/containd/pkg/dp/dpi"
)

func TestOrderingOperatorsNeedNumericValue(t *testing.T) {
	for _, op := range []string{"gt", "lt", "gte", "lte"} {
		cond := Condition{Op: op, Value: float64(128)}
		for _, v := range []any{nil, "128", true} {
			if evalCondition(cond, v) {
				t.Fatalf("%s matched non-numeric %v", op, v)
			}
		}
	}
	if !evalCondition(Condition{Op: "gte", Value: float64(128)}, uint8(128)) {
		t.Fatal("gte must match an equal value")
	}
	if !evalCondition(Condition{Op: "lte", Value: float64(128)}, uint8(128)) {
		t.Fatal("lte must match an equal value")
	}
}

func TestGTEDoesNotMatchAbsentAttribute(t *testing.T) {
	e := New()
	e.Add(Signature{ID: "GTE", Protocol: "modbus", Conditions: []Condition{{Field: "function_code", Op: "gte", Value: float64(128)}}})
	malformed := dpi.Event{Proto: "modbus", Kind: "malformed", Attributes: map[string]any{"error": "bad length"}}
	if len(e.Match(malformed)) != 0 {
		t.Fatal("gte matched an event without function_code")
	}
}
