// SPDX-License-Identifier: Apache-2.0
package config

import (
	"reflect"
	"testing"
)

func TestICSPredicateEmpty(t *testing.T) {
	zero := uint8(0)
	fields := []ICSPredicate{
		{Protocol: "modbus"}, {FunctionCode: []uint8{0}}, {UnitID: &zero},
		{Addresses: []string{"0"}}, {ObjectClasses: []uint16{0}},
		{ReadOnly: true}, {WriteOnly: true}, {Direction: "request"},
		{TypeIDs: []int{1}}, {Classes: []string{"monitor"}},
		{CA: []uint16{0}}, {IOA: []IOARange{{Start: 0, End: 0}}},
	}
	// Guard additions to the model: each packet field needs a fixture here.
	if len(fields) != reflect.TypeFor[ICSPredicate]().NumField()-1 {
		t.Fatal("add a predicate emptiness fixture for the new field")
	}
	for _, p := range fields {
		if p.Empty() {
			t.Errorf("nonempty predicate: %+v", p)
		}
	}
	for _, p := range []ICSPredicate{{}, {Mode: "enforce"}, {Mode: "learn"}, {Protocol: " ", Direction: " "}} {
		if !p.Empty() {
			t.Errorf("empty predicate: %+v", p)
		}
	}
}
