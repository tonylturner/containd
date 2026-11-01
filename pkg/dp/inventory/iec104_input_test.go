// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 containd Authors

package inventory

import (
	"testing"

	"github.com/tonylturner/containd/pkg/dp/dpi"
	"github.com/tonylturner/containd/pkg/dp/ics/eventfields"
)

func TestIEC104ObservationFromEvents(t *testing.T) {
	events := []dpi.Event{
		{Attributes: map[string]any{eventfields.KeyCA: uint16(7), eventfields.KeyTypeID: uint8(46), eventfields.KeyCause: uint8(6), eventfields.KeyIOA: uint32(101)}},
		{Attributes: map[string]any{eventfields.KeyIOA: uint32(102)}},
	}
	o, ok := IEC104ObservationFromEvents(events)
	if !ok || o.CA != 7 || o.TypeID != 46 || o.COT != 6 || len(o.IOAs) != 2 || o.IsCommand() {
		t.Fatal(o, ok)
	}
	o.ControlDirection = true
	if !o.IsCommand() {
		t.Fatal("client command not recognized")
	}
	for _, evs := range [][]dpi.Event{nil, {{Attributes: map[string]any{eventfields.KeyAPCIType: "U"}}}} {
		if _, ok := IEC104ObservationFromEvents(evs); ok {
			t.Fatal("APCI-only frame became a CA")
		}
	}
}
