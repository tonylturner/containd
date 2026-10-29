// SPDX-License-Identifier: Apache-2.0
package dnp3

import (
	"encoding/binary"
	"testing"

	"github.com/tonylturner/containd/pkg/dp/ics/eventfields"
	"github.com/tonylturner/containd/pkg/dp/ics/eventfields/decodertest"
)

func TestObjectWalkCoverageEmission(t *testing.T) {
	headerBudget := make([]byte, 0, (maxObjectHeaders+1)*3)
	for range maxObjectHeaders + 1 {
		headerBudget = append(headerBudget, 60, 2, 6)
	}
	pointBudget := []byte{1, 1, 8}
	pointBudget = binary.LittleEndian.AppendUint16(pointBudget, maxDecodedPoints+1)
	sharedBudget := append([]byte{1, 1, 8, 0, 32}, make([]byte, maxDecodedPoints/8)...)
	sharedBudget = append(sharedBudget, 1, 1, 7, 1, 0xff)
	for _, tc := range []struct {
		name       string
		fc         byte
		objects    []byte
		incomplete bool
		points     int
	}{
		{"unknown group", FuncResponse, []byte{99, 1, 7, 1, 0}, true, 0},
		{"unsupported variation", FuncResponse, []byte{1, 99, 7, 1, 0}, true, 0},
		{"size prefixed", FuncResponse, []byte{70, 3, 0x5b, 1, 3, 0, 1, 2, 3}, true, 0},
		{"free format without size prefix", FuncRead, []byte{1, 2, 0x0b, 1}, true, 0},
		{"truncated size prefixed", FuncResponse, []byte{70, 3, 0x5b, 1, 3, 0, 1}, true, 0},
		{"truncated header", FuncRead, []byte{1}, true, 0},
		{"truncated range", FuncRead, []byte{1, 2, 1, 0}, true, 0},
		{"truncated value", FuncResponse, []byte{1, 2, 7, 1}, true, 0},
		{"partial points", FuncResponse, []byte{1, 2, 0x17, 2, 7, 1, 9}, true, 1},
		{"reserved range", FuncRead, []byte{1, 2, 0x0c}, true, 0},
		{"reserved prefix", FuncRead, []byte{1, 2, 0x76}, true, 0},
		{"reserved qualifier bit", FuncRead, []byte{1, 2, 0x86}, true, 0},
		{"reversed range", FuncRead, []byte{1, 2, 0, 5, 1}, true, 0},
		{"header budget", FuncRead, headerBudget, true, 0},
		{"point budget", FuncResponse, pointBudget, true, 0},
		{"shared point budget", FuncResponse, sharedBudget, true, maxDecodedPoints},
		{"complete no objects", FuncRead, nil, false, 0},
		{"complete read all", FuncRead, []byte{60, 2, 6}, false, 0},
		{"complete indexed read", FuncRead, []byte{1, 2, 0x17, 2, 7, 9}, false, 2},
		{"complete values", FuncResponse, []byte{1, 2, 0x17, 2, 7, 1, 9, 0}, false, 2},
		{"complete packed", FuncResponse, []byte{1, 1, 0, 0, 9, 0xff, 3}, false, 10},
	} {
		t.Run(tc.name, func(t *testing.T) {
			data := []byte{0xc0, 0xc0, tc.fc}
			if IsResponse(tc.fc) {
				data = append(data, 0, 0)
			}
			// The fragment projection is also used after multi-link assembly,
			// so budget fixtures need not fit a single link frame.
			data = append(data, tc.objects...)
			ev := frameEvents(dnp3State(), &DNP3Frame{FunctionCode: tc.fc, Data: data}, nil)[0]
			for form, attrs := range decodertest.Forms(t, ev.Attributes) {
				incomplete, present := eventfields.Bool(attrs, eventfields.KeyCoverageIncomplete)
				if present != tc.incomplete || incomplete != tc.incomplete {
					t.Fatalf("%s coverage=%v present=%v want=%v", form, incomplete, present, tc.incomplete)
				}
			}
			headers, _ := ev.Attributes["objects"].([]ObjectHeader)
			points := 0
			for _, h := range headers {
				points += len(h.Points)
			}
			if points != tc.points {
				t.Fatalf("points=%d want=%d", points, tc.points)
			}
			if tc.name == "partial points" && (headers[0].Count != 2 || headers[0].Covered != 6 || *headers[0].Points[0].Index != 7) {
				t.Fatalf("partial evidence lost: %+v", headers[0])
			}
		})
	}
}

func TestTruncatedApplicationCoverageEmission(t *testing.T) {
	ev := frameEvents(dnp3State(), &DNP3Frame{FunctionCode: FuncResponse, Data: []byte{0xc0, 0xc0, FuncResponse}}, nil)[0]
	if incomplete, _ := eventfields.Bool(ev.Attributes, eventfields.KeyCoverageIncomplete); !incomplete {
		t.Fatal(ev)
	}
}
