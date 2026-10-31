// SPDX-License-Identifier: Apache-2.0
package project

import (
	"testing"

	"github.com/tonylturner/containd/pkg/dp/dpi"
	"github.com/tonylturner/containd/pkg/dp/ics/eventfields"
)

func TestIEC104CommandContextPresence(t *testing.T) {
	for id := range 256 {
		for _, apci := range []string{"I", "S", "U"} {
			a := map[string]any{eventfields.KeyAPCIType: apci, eventfields.KeyTypeID: uint8(id), eventfields.KeyValue: uint8(1), eventfields.KeyQualifier: uint8(0)}
			c := iecObject(dpi.Event{Attributes: a}, nil).IEC104
			want := apci == "I" && (id == 45 || id == 46 || id == 47 || id == 58 || id == 59 || id == 60)
			if (c.CommandState != nil) != want || (c.CommandQualifier != nil) != want {
				t.Fatalf("type %d APCI %s: %+v", id, apci, c)
			}
			if want && (*c.CommandState != 1 || *c.CommandQualifier != 0) {
				t.Fatal("value lost")
			}
			delete(a, eventfields.KeyValue)
			delete(a, eventfields.KeyQualifier)
			c = iecObject(dpi.Event{Attributes: a}, nil).IEC104
			if c.CommandState != nil || c.CommandQualifier != nil {
				t.Fatal("absent fields fabricated")
			}
		}
	}
}
