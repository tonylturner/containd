// SPDX-License-Identifier: Apache-2.0
package rules

import (
	"fmt"
	"testing"
)

func TestGateStableZoneAllocation(t *testing.T) {
	previous := []GateZone{{Name: "retired", Index: 1}, {Name: "wan", Index: 7}}
	input := GateSelection{Zones: []GateZone{{Name: "new", Index: 1, Devices: []string{"eth2"}}, {Name: "wan", Index: 2}}}
	got, err := input.WithStableZoneIndices(previous)
	if err != nil {
		t.Fatal(err)
	}
	if got.Zones[0].Index != 2 || got.Zones[1].Index != 7 {
		t.Fatalf("allocation = %+v", got.Zones)
	}
	got.Zones[0].Devices[0] = "edited"
	if input.Zones[0].Index != 1 || input.Zones[0].Devices[0] != "eth2" || previous[1].Index != 7 {
		t.Fatal("allocation mutated inputs")
	}
}

func TestGateStableZoneAllocationRejectsAmbiguousInputs(t *testing.T) {
	for _, previous := range [][]GateZone{
		{{Name: "a", Index: 0}}, {{Name: "a", Index: 1}, {Name: "b", Index: 1}},
		{{Name: "a", Index: 1}, {Name: "a", Index: 2}}, {{Name: "", Index: 1}},
	} {
		if _, err := (GateSelection{}).WithStableZoneIndices(previous); err == nil {
			t.Fatal("invalid previous allocation accepted")
		}
	}
	if _, err := (GateSelection{Zones: []GateZone{{Name: "a"}, {Name: "a"}}}).WithStableZoneIndices(nil); err == nil {
		t.Fatal("duplicate new name accepted")
	}
	var previous []GateZone
	for i := 1; i <= 255; i++ {
		previous = append(previous, GateZone{Name: fmt.Sprintf("old-%d", i), Index: uint8(i)})
	}
	if _, err := (GateSelection{Zones: []GateZone{{Name: "new"}}}).WithStableZoneIndices(previous); err == nil {
		t.Fatal("retired index reused without session retirement")
	}
}
