// SPDX-License-Identifier: Apache-2.0
package dnp3

import (
	"fmt"
	"slices"
	"testing"

	"github.com/tonylturner/containd/pkg/dp/dpi"
	"github.com/tonylturner/containd/pkg/dp/ics/eventfields"
)

func TestTransportBoundaryTruncation(t *testing.T) {
	for _, tc := range []struct {
		name string
		data []byte
	}{
		{"fixed values", []byte{0xc0, 0xc0, FuncResponse, 0, 0, 30, 1, 7, 2, 1, 2, 3, 4, 5, 1, 2, 3, 4, 5}},
		{"size prefixed", []byte{0xc0, 0xc0, FuncResponse, 0, 0, 70, 3, 0x5b, 2, 3, 0, 1, 2, 3, 2, 0, 4, 5}},
		{"indexed read", []byte{0xc0, 0xc0, FuncRead, 30, 1, 0x28, 2, 0, 1, 0, 2, 0}},
		{"packed bits", []byte{0xc0, 0xc0, FuncResponse, 0, 0, 1, 1, 7, 16, 0xff, 0xff}},
	} {
		for cut := 1; cut <= len(tc.data); cut++ {
			for _, final := range []bool{false, true} {
				t.Run(fmt.Sprintf("%s/cut%d/final%v", tc.name, cut, final), func(t *testing.T) {
					data := slices.Clone(tc.data[:cut])
					data[0] &^= TransportFIN
					if final {
						data[0] |= TransportFIN
					}
					raw := linkFrame(0x44, data)
					res, err := NewDecoder().ParseStream(dnp3State(), dpi.StreamView{Bytes: append(raw, readFrame...)})
					if err != nil || len(res.Frames) != 2 {
						t.Fatalf("result=%+v err=%v", res, err)
					}
					var codes []string
					for _, ev := range res.Frames[0].Events {
						cs, _ := eventfields.Strings(ev.Attributes, eventfields.KeyConformance)
						codes = append(codes, cs...)
						if cut >= 3 && ev.Attributes[eventfields.KeyFunctionCode] != data[2] {
							t.Fatal("lost decoded function code")
						}
					}
					if !final && len(codes) != 0 {
						t.Fatalf("normal transport boundary: %v", codes)
					}
					if final && cut < 3 && !slices.Contains(codes, "dnp3.application_header") {
						t.Fatalf("missing final-segment header finding: %v", codes)
					}
					// Cuts immediately before an object header, or at the
					// complete fragment boundary, are not truncated walks.
					headerEnd := 3
					if IsResponse(tc.data[2]) {
						headerEnd = 5
					}
					if final && cut >= 3 && cut < headerEnd && !slices.Contains(codes, "dnp3.application_header") {
						t.Fatalf("missing IIN finding: %v", codes)
					}
					if final && cut > headerEnd && cut < len(tc.data) && !slices.Contains(codes, "dnp3.object_walk") {
						t.Fatalf("missing final-segment object finding: %v", codes)
					}
					if cut == len(tc.data) && len(codes) != 0 {
						t.Fatalf("complete fragment: %v", codes)
					}
				})
			}
		}
	}
}

func TestCompletedSegmentsInspectInvalidContent(t *testing.T) {
	for _, objects := range [][]byte{
		{99, 9, 7, 1},      // unknown value size, even without value bytes
		{1, 2, 0x0c},       // reserved range
		{1, 2, 0x76},       // reserved prefix
		{1, 2, 0x87},       // reserved bit plus truncated range
		{1, 2, 0, 5, 1},    // stop before start
		{1, 1, 0x17, 1, 0}, // packed values cannot use index prefixes
	} {
		for _, final := range []bool{false, true} {
			data := append([]byte{TransportFIR, 0xc0, FuncResponse, 0, 0}, objects...)
			if final {
				data[0] |= TransportFIN
			}
			raw := linkFrame(0x44, data)
			events, err := NewDecoder().OnPacket(dnp3State(), &dpi.ParsedPacket{Payload: raw})
			if !final {
				if err != nil || len(events) != 0 {
					t.Fatalf("pending fragment events=%v err=%v", events, err)
				}
				continue
			}
			if err != nil || len(events) != 1 {
				t.Fatalf("events=%v err=%v", events, err)
			}
			codes, _ := eventfields.Strings(events[0].Attributes, eventfields.KeyConformance)
			if objects[0] == 99 {
				codes, _ = eventfields.Strings(events[0].Attributes, eventfields.KeyUndecoded)
				if !slices.Equal(codes, []string{"dnp3.object_unsupported"}) {
					t.Fatal(codes)
				}
				continue
			}
			if !slices.Equal(codes, []string{"dnp3.object_walk"}) {
				t.Fatalf("objects=%x final=%v codes=%v", objects, final, codes)
			}
		}
	}
}

func TestNonFinalTruncationStillReportsDataCRC(t *testing.T) {
	raw := linkFrame(0x44, []byte{TransportFIR, 0xc0, FuncResponse, 0})
	raw[len(raw)-1] ^= 1
	events, err := NewDecoder().OnPacket(dnp3State(), &dpi.ParsedPacket{Payload: raw})
	if err != nil || len(events) != 1 {
		t.Fatalf("events=%v err=%v", events, err)
	}
	codes, _ := eventfields.Strings(events[0].Attributes, eventfields.KeyConformance)
	if !slices.Equal(codes, []string{"dnp3.data_crc"}) {
		t.Fatal(codes)
	}
}
