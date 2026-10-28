// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

package dnp3

import (
	"reflect"
	"testing"
	"time"

	"github.com/tonylturner/containd/pkg/dp/dpi"
	"github.com/tonylturner/containd/pkg/dp/flow"
)

type headerWant struct {
	group, variation, qualifier uint8
	count                       uint64
}

func headerSummary(hs []ObjectHeader) []headerWant {
	out := []headerWant{}
	for _, h := range hs {
		out = append(out, headerWant{h.Group, h.Variation, h.Qualifier, h.Count})
	}
	return out
}

// Object headers are group, variation, qualifier (prefix code bits 4-6,
// range code bits 0-3) and a range field, followed by the objects
// (IEEE 1815-2012 application layer).
func TestParseObjectHeaders(t *testing.T) {
	cases := []struct {
		name string
		fc   uint8
		data []byte
		want []headerWant
	}{
		{
			name: "read: all objects then 1-octet start/stop",
			fc:   FuncRead,
			data: []byte{0x01, 0x02, 0x06, 0x1E, 0x02, 0x00, 0x00, 0x04},
			want: []headerWant{{1, 2, 0x06, 0}, {30, 2, 0x00, 5}},
		},
		{
			name: "read: 1-octet count",
			fc:   FuncRead,
			data: []byte{0x0C, 0x01, 0x07, 0x03},
			want: []headerWant{{12, 1, 0x07, 3}},
		},
		{
			name: "read: 1-octet index prefix lists indexes, no values",
			fc:   FuncRead,
			data: []byte{0x1E, 0x02, 0x17, 0x02, 0x03, 0x07, 0x01, 0x02, 0x06},
			want: []headerWant{{30, 2, 0x17, 2}, {1, 2, 0x06, 0}},
		},
		{
			name: "read: 2-octet start/stop and 4-octet count",
			fc:   FuncRead,
			data: []byte{
				0x1E, 0x01, 0x01, 0x0A, 0x00, 0x13, 0x00, // 10..19
				0x14, 0x01, 0x09, 0x70, 0x11, 0x01, 0x00, // count 70000
			},
			want: []headerWant{{30, 1, 0x01, 10}, {20, 1, 0x09, 70000}},
		},
		{
			name: "response: values are skipped, not read as headers",
			fc:   FuncResponse,
			data: []byte{
				0x1E, 0x01, 0x00, 0x00, 0x01, // g30v1 0..1
				0x01, 0x46, 0x00, 0x00, 0x00, // value 0x00004601 with flag 0x01
				0x01, 0x46, 0x00, 0x00, 0x00,
				0x01, 0x02, 0x00, 0x00, 0x00, 0x81, // g1v2 0..0, flags 0x81
			},
			want: []headerWant{{30, 1, 0x00, 2}, {1, 2, 0x00, 1}},
		},
		{
			name: "response: packed bits then 2-octet start/stop",
			fc:   FuncResponse,
			data: []byte{
				0x01, 0x01, 0x00, 0x00, 0x09, 0xFF, 0x03, // g1v1 0..9: 10 bits in 2 octets
				0x1E, 0x04, 0x01, 0x00, 0x00, 0x00, 0x00, 0x46, 0x00, // g30v4 0..0
			},
			want: []headerWant{{1, 1, 0x00, 10}, {30, 4, 0x01, 1}},
		},
		{
			name: "operate: CROBs with 1- and 2-octet index prefixes",
			fc:   FuncOperate,
			data: []byte{
				0x0C, 0x01, 0x17, 0x01, 0x05, 0x03, 0x01, 0x64, 0, 0, 0, 0x64, 0, 0, 0, 0x00,
				0x0C, 0x01, 0x28, 0x01, 0x00, 0x06, 0x00, 0x04, 0x01, 0x64, 0, 0, 0, 0x64, 0, 0, 0, 0x00,
			},
			want: []headerWant{{12, 1, 0x17, 1}, {12, 1, 0x28, 1}},
		},
		{
			name: "free format: sized but uninspected values stop the walk",
			fc:   0x19, // open file
			data: []byte{
				0x46, 0x03, 0x5B, 0x01, 0x03, 0x00, 0xAA, 0xBB, 0xCC, // g70v3, one 3-octet object
				0x32, 0x01, 0x07, 0x01, 1, 2, 3, 4, 5, 6, // g50v1 count 1
			},
			want: []headerWant{{70, 3, 0x5B, 1}},
		},
		{
			name: "unknown variation stops the walk",
			fc:   FuncResponse,
			data: []byte{0x63, 0x09, 0x00, 0x00, 0x00, 0x46, 0x00, 0x06, 0x01, 0x02},
			want: []headerWant{{99, 9, 0x00, 1}},
		},
		{
			name: "reserved range code: header kept, walk stops",
			fc:   FuncRead,
			data: []byte{0x46, 0x01, 0x0C, 0x01, 0x02, 0x06},
			want: []headerWant{{70, 1, 0x0C, 0}},
		},
		{
			name: "stop before start: header kept, walk stops",
			fc:   FuncRead,
			data: []byte{0x1E, 0x02, 0x00, 0x05, 0x01, 0x01, 0x02, 0x06},
			want: []headerWant{{30, 2, 0x00, 0}},
		},
		{
			name: "truncated range field: readable header retained",
			fc:   FuncRead,
			data: []byte{0x1E, 0x02, 0x01, 0x05},
			want: []headerWant{{30, 2, 0x01, 0}},
		},
		{
			name: "values shorter than the range: header kept, walk stops",
			fc:   FuncResponse,
			data: []byte{0x1E, 0x01, 0x00, 0x00, 0x01, 0x01, 0x46},
			want: []headerWant{{30, 1, 0x00, 2}},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := headerSummary(ParseObjectHeaders(tc.data, 0, tc.fc))
			if !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("headers = %+v, want %+v", got, tc.want)
			}
		})
	}
	if hs := ParseObjectHeaders([]byte{0x01}, 1, FuncRead); hs != nil {
		t.Fatalf("offset at end: %+v", hs)
	}
}

func TestDecoderObjectGroupsSkipResponseValues(t *testing.T) {
	dec := NewDecoder()
	state := flow.NewState(keyFor("10.0.0.2", "10.0.0.1", 20000, 12345), time.Now())
	// The g30v1 value octets were once read as the next object header.
	userData := []byte{
		0xC0, 0xC0, 0x81, 0x00, 0x00,
		0x1E, 0x01, 0x00, 0x00, 0x00, 0x01, 0x46, 0x00, 0x07, 0x00,
		0x01, 0x02, 0x00, 0x00, 0x00, 0x81,
	}
	raw := buildTestFrame(uint8(5+len(userData)), 0x44, 0x0002, 0x0001, userData)
	events, err := dec.OnPacket(state, &dpi.ParsedPacket{Payload: raw})
	if err != nil || len(events) != 1 {
		t.Fatalf("OnPacket = %d events, %v", len(events), err)
	}
	if got := events[0].Attributes["object_groups"]; got != "30,1" {
		t.Fatalf("object_groups = %v, want 30,1", got)
	}
	if got := events[0].Attributes["object_count"]; got != uint16(1) {
		t.Fatalf("object_count = %#v, want uint16(1)", got)
	}
}
