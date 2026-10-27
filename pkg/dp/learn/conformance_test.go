// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 containd Authors

package learn

import (
	"testing"

	"github.com/tonylturner/containd/pkg/dp/dpi"
	"github.com/tonylturner/containd/pkg/dp/ics/eventfields"
)

// RecordEvent is also the offline PCAP policy-generation gate.
func TestConformanceNeverLearned(t *testing.T) {
	for _, proto := range []string{"modbus", "dnp3", "cip"} {
		for _, codes := range []any{[]string{proto + ".test"}, []any{proto + ".test"}} {
			l := New()
			l.RecordEvent("10.0.0.1", "10.0.0.2", dpi.Event{
				Proto: proto, Kind: "request", Attributes: map[string]any{
					"function_code": uint8(3), "unit_id": uint8(1),
					"address": uint16(0), "quantity": uint16(1), "is_write": false,
					eventfields.KeyConformance: codes,
				},
			})
			if len(l.Profiles()) != 0 || len(l.GenerateRules()) != 0 {
				t.Fatalf("%s findings generated permissions", proto)
			}
		}
	}
}
