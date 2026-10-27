// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

package learn

import (
	"testing"

	"github.com/tonylturner/containd/pkg/dp/dpi"
)

func TestLearnerRejectsFractionalCodes(t *testing.T) {
	l := New()
	l.RecordEvent("10.0.0.1", "10.0.0.2", dpi.Event{Proto: "modbus", Kind: "request", Attributes: map[string]any{
		"function_code": 3.7,
		"unit_id":       1.5,
	}})
	l.RecordEvent("10.0.0.1", "10.0.0.2", dpi.Event{Proto: "modbus", Kind: "request", Attributes: map[string]any{
		"function_code": float64(3), // the JSON form of a real FC
		"unit_id":       uint8(1),
		"address":       uint16(10),
		"quantity":      uint16(1),
	}})
	profiles := l.Profiles()
	if len(profiles) != 1 {
		t.Fatalf("profiles = %+v", profiles)
	}
	p := profiles[0]
	if len(p.FunctionCodes) != 1 || !p.FunctionCodes[3] {
		t.Fatalf("function codes = %v, want only 3 (3.7 must not truncate to 3)", p.FunctionCodes)
	}
	if len(p.UnitIDs) != 1 || !p.UnitIDs[1] {
		t.Fatalf("unit ids = %v, want only 1", p.UnitIDs)
	}
}
