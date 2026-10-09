// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

package dnp3

import (
	"testing"
	"time"

	"github.com/tonylturner/containd/pkg/dp/dpi"
	"github.com/tonylturner/containd/pkg/dp/flow"
	"github.com/tonylturner/containd/pkg/dp/ics/eventfields"
	"github.com/tonylturner/containd/pkg/dp/ics/eventfields/eventfieldstest"
)

// Readers use the eventfields accessors on these keys (spec §4 "ICS field
// drift"); the decoder must emit values those accessors read exactly. The
// object_groups wire key stays a comma-separated string.
func TestDecodedFieldsReadThroughAccessors(t *testing.T) {
	state := flow.NewState(keyFor("10.0.0.1", "10.0.0.2", 12345, 20000), time.Now())
	cases := []struct {
		name     string
		userData []byte
		fc       uint8
		isWrite  bool
		groups   string
	}{
		{"cold restart", []byte{0xC0, 0xC0, FuncColdRestart}, 13, true, ""},
		{"read class data", []byte{0xC0, 0xC0, FuncRead, 0x3C, 0x02, 0x06, 0x3C, 0x03, 0x06, 0x46, 0x05, 0x06}, 1, false, "60,60,70"},
	}
	for _, tc := range cases {
		raw := buildTestFrame(uint8(5+len(tc.userData)), 0xC4, 0x0001, 0x0002, tc.userData)
		events, err := NewDecoder().OnPacket(state, &dpi.ParsedPacket{Payload: raw})
		if err != nil || len(events) != 1 {
			t.Fatalf("%s: OnPacket = %d events, %v", tc.name, len(events), err)
		}
		if events[0].Proto != eventfields.ProtoDNP3 {
			t.Fatalf("%s: proto %q", tc.name, events[0].Proto)
		}
		for form, attrs := range eventfieldstest.Forms(t, events[0].Attributes) {
			fc, okFC := eventfields.Uint8(attrs, eventfields.KeyFunctionCode)
			isWrite, okWrite := eventfields.Bool(attrs, eventfields.KeyIsWrite)
			if !okFC || !okWrite || fc != tc.fc || isWrite != tc.isWrite {
				t.Fatalf("%s/%s: fc=%d,%v is_write=%v,%v", tc.name, form, fc, okFC, isWrite, okWrite)
			}
			groups, okGroups := eventfields.String(attrs, eventfields.KeyObjectGroups)
			if okGroups != (tc.groups != "") || groups != tc.groups {
				t.Fatalf("%s/%s: object_groups=%q,%v want %q", tc.name, form, groups, okGroups, tc.groups)
			}
		}
	}
}
