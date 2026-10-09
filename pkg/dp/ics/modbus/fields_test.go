// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

package modbus

import (
	"testing"
	"time"

	"github.com/tonylturner/containd/pkg/dp/dpi"
	"github.com/tonylturner/containd/pkg/dp/flow"
	"github.com/tonylturner/containd/pkg/dp/ics/eventfields"
	"github.com/tonylturner/containd/pkg/dp/ics/eventfields/eventfieldstest"
)

// Readers use the eventfields accessors on these keys (spec §4 "ICS field
// drift"); the decoder must emit values those accessors read exactly.
func TestDecodedFieldsReadThroughAccessors(t *testing.T) {
	state := flow.NewState(keyFor("10.0.0.1", "10.0.0.2", 12345, 502), time.Now())
	cases := []struct {
		name    string
		raw     []byte
		fc      uint8
		unit    uint8
		isWrite bool
	}{
		// Write single register (FC 6) to unit 7.
		{"write", []byte{0x00, 0x09, 0x00, 0x00, 0x00, 0x06, 0x07, 0x06, 0x00, 0x01, 0x00, 0x2A}, 6, 7, true},
		// Exception response to FC 16: function_code is the base code.
		{"exception", []byte{0x00, 0x09, 0x00, 0x00, 0x00, 0x03, 0x07, 0x90, 0x02}, 16, 7, true},
		// Read holding registers (FC 3), unit 0.
		{"read", []byte{0x00, 0x01, 0x00, 0x00, 0x00, 0x06, 0x00, 0x03, 0x00, 0x00, 0x00, 0x02}, 3, 0, false},
	}
	for _, tc := range cases {
		events, err := NewDecoder().OnPacket(state, &dpi.ParsedPacket{Payload: tc.raw})
		if err != nil || len(events) != 1 {
			t.Fatalf("%s: OnPacket = %d events, %v", tc.name, len(events), err)
		}
		if events[0].Proto != eventfields.ProtoModbus {
			t.Fatalf("%s: proto %q", tc.name, events[0].Proto)
		}
		for form, attrs := range eventfieldstest.Forms(t, events[0].Attributes) {
			fc, okFC := eventfields.Uint8(attrs, eventfields.KeyFunctionCode)
			unit, okUnit := eventfields.Uint8(attrs, eventfields.KeyUnitID)
			isWrite, okWrite := eventfields.Bool(attrs, eventfields.KeyIsWrite)
			if !okFC || !okUnit || !okWrite || fc != tc.fc || unit != tc.unit || isWrite != tc.isWrite {
				t.Fatalf("%s/%s: fc=%d,%v unit=%d,%v is_write=%v,%v", tc.name, form, fc, okFC, unit, okUnit, isWrite, okWrite)
			}
		}
	}
}
