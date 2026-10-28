// SPDX-License-Identifier: Apache-2.0
package dnp3

import (
	"slices"
	"testing"

	"github.com/tonylturner/containd/pkg/dp/dpi"
	"github.com/tonylturner/containd/pkg/dp/ics/eventfields"
)

func TestCROBEncodingEvidence(t *testing.T) {
	for _, tc := range []struct {
		name            string
		control, status byte
		bad             bool
	}{
		{"queue-clear", 0x31, 0, false},
		{"deprecated-status", 1, 126, false},
		{"reserved-operation", 5, 0, true},
		{"reserved-trip-close", 0xc1, 0, true},
		{"reserved-status", 1, 19, true},
		{"undefined-sentinel", 1, 127, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			objects := []byte{12, 1, 0x17, 1, 7, tc.control, 2, 255, 255, 255, 255, 0, 0, 0, 0, tc.status}
			events, err := NewDecoder().OnPacket(dnp3State(), &dpi.ParsedPacket{Payload: appFrame(0, FuncOperate, objects...)})
			if err != nil {
				t.Fatal(err)
			}
			ev := expectOne(t, events)
			codes, _ := eventfields.Strings(ev.Attributes, eventfields.KeyConformance)
			if slices.Contains(codes, "dnp3.crob_value") != tc.bad {
				t.Fatal(codes)
			}
			if _, present := ev.Attributes[eventfields.KeyUndecoded]; present {
				t.Fatal("complete CROB was not inspected")
			}
			h := ev.Attributes["objects"].([]ObjectHeader)[0]
			point := h.Points[0]
			value := point.CROB
			if *point.Index != 7 || value.Control != tc.control || value.Status != tc.status || value.Count != 2 || value.OnTime != ^uint32(0) || value.OffTime != 0 {
				t.Fatal(point, value)
			}
			if tc.name == "queue-clear" && (!value.Queue || !value.Clear || value.Operation != 1 || value.TripClose != 0) {
				t.Fatal(value)
			}
		})
	}
}

func TestObjectEvidenceBudget(t *testing.T) {
	// A small packed value can name many points. Separate headers must not
	// multiply the per-fragment evidence budget.
	data := []byte{1, 1, 8, 0, 32} // 8192 one-bit objects, no manufactured index
	data = append(data, make([]byte, maxDecodedPoints/8)...)
	data = append(data, 1, 1, 7, 1, 0xff)
	headers, stop := parseObjectHeaders(data, 0, FuncResponse)
	if stop != walkLimited || len(headers) != 2 || len(headers[0].Points) != maxDecodedPoints || len(headers[1].Points) != 0 {
		t.Fatal("point budget not shared", stop, len(headers))
	}
	// Header-only requests have a separate metadata bound even with no values.
	data = nil
	for i := 0; i <= maxObjectHeaders; i++ {
		data = append(data, 60, 2, 6)
	}
	headers, stop = parseObjectHeaders(data, 0, FuncRead)
	if stop != walkLimited || len(headers) != maxObjectHeaders {
		t.Fatal("unbounded headers", stop, len(headers))
	}
}
