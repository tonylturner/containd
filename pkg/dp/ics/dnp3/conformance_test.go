// SPDX-License-Identifier: Apache-2.0
package dnp3

import (
	"bytes"
	"reflect"
	"testing"

	"github.com/tonylturner/containd/pkg/dp/dpi"
	"github.com/tonylturner/containd/pkg/dp/ics/eventfields"
	"github.com/tonylturner/containd/pkg/dp/ics/eventfields/decodertest"
)

func TestConformanceTwins(t *testing.T) {
	for _, tc := range []struct {
		name, code string
		bad, good  []byte
	}{
		{"short FIR", "dnp3.application_header", []byte{0xc0, 0xc0}, []byte{0xc0, 0xc0, FuncRead}},
		{"short IIN", "dnp3.application_header", []byte{0xc0, 0xc0, FuncResponse, 0}, []byte{0xc0, 0xc0, FuncResponse, 0, 0}},
		{"short object", "dnp3.object_walk", []byte{0xc0, 0xc0, FuncRead, 1}, []byte{0xc0, 0xc0, FuncRead, 1, 2, 6}},
		{"short range", "dnp3.object_walk", []byte{0xc0, 0xc0, FuncRead, 1, 2, 1, 0}, []byte{0xc0, 0xc0, FuncRead, 1, 2, 1, 0, 0, 0, 0}},
		{"unknown value size", "dnp3.object_unsupported", []byte{0xc0, 0xc0, FuncResponse, 0, 0, 99, 9, 7, 1, 0}, []byte{0xc0, 0xc0, FuncResponse, 0, 0, 1, 2, 7, 1, 0}},
		{"reserved range", "dnp3.object_walk", []byte{0xc0, 0xc0, FuncRead, 1, 2, 0x0c}, []byte{0xc0, 0xc0, FuncRead, 1, 2, 6}},
		{"reserved prefix", "dnp3.object_walk", []byte{0xc0, 0xc0, FuncRead, 1, 2, 0x76}, []byte{0xc0, 0xc0, FuncRead, 1, 2, 6}},
		{"reserved bit", "dnp3.object_walk", []byte{0xc0, 0xc0, FuncRead, 1, 2, 0x86}, []byte{0xc0, 0xc0, FuncRead, 1, 2, 6}},
		{"short values", "dnp3.object_walk", []byte{0xc0, 0xc0, FuncResponse, 0, 0, 30, 1, 7, 1, 0}, []byte{0xc0, 0xc0, FuncResponse, 0, 0, 30, 1, 7, 1, 0, 0, 0, 0, 0}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			for _, bad := range []bool{true, false} {
				data := tc.good
				if bad {
					data = tc.bad
				}
				raw := linkFrame(0xc4, data)
				res, err := NewDecoder().ParseStream(dnp3State(), dpi.StreamView{Bytes: append(raw, readFrame...)})
				if err != nil || len(res.Frames) != 2 || len(res.Frames[0].Events) != 1 {
					t.Fatalf("frames=%+v err=%v", res, err)
				}
				for form, attrs := range decodertest.Forms(t, res.Frames[0].Events[0].Attributes) {
					key := eventfields.KeyConformance
					if tc.code == "dnp3.object_unsupported" {
						key = eventfields.KeyUndecoded
					}
					got, _ := eventfields.Strings(attrs, key)
					var want []string
					if bad {
						want = []string{tc.code}
					}
					if !reflect.DeepEqual(got, want) {
						t.Fatalf("%s bad=%v got=%v want=%v", form, bad, got, want)
					}
				}
			}
		})
	}
}

func TestDataCRCFindingsOnApplicationAndContinuation(t *testing.T) {
	for _, data := range [][]byte{
		{0xc0, 0xc0, FuncRead},
		{0x80, 1, 2, 3}, // no application event unless corrupt
		append([]byte{0xc0, 0xc0, FuncRead}, bytes.Repeat([]byte{1, 2, 6}, 10)...), // several CRC blocks
	} {
		raw := linkFrame(0xc4, data)
		for block := 10; block < len(raw); {
			size := min(16, len(raw)-block-2)
			for _, bad := range []bool{true, false} {
				wire := append([]byte(nil), raw...)
				if bad {
					wire[block+size] ^= 1
				}
				res, err := NewDecoder().ParseStream(dnp3State(), dpi.StreamView{Bytes: wire})
				if err != nil || res.Consumed != len(wire) {
					t.Fatalf("%+v %v", res, err)
				}
				events := res.Frames[0].Events

				if len(events) != 1 {
					t.Fatal(events)
				}
				codes, _ := eventfields.Strings(events[0].Attributes, eventfields.KeyConformance)
				found := false
				for _, c := range codes {
					if c == "dnp3.data_crc" {
						found = true
					}
				}
				if found != bad {
					t.Fatalf("bad=%v codes=%v", bad, codes)
				}
				if data[0]&TransportFIR == 0 {
					if _, ok := events[0].Attributes[eventfields.KeyFunctionCode]; ok {
						t.Fatal("invented continuation FC")
					}
				}
			}
			block += size + 2
		}
	}
}

func TestStoppedWalkRetainsOnlyReadFields(t *testing.T) {
	raw := linkFrame(0xc4, []byte{0xc0, 0xc0, FuncRead, 30, 1, 1, 0})
	events, err := NewDecoder().OnPacket(dnp3State(), &dpi.ParsedPacket{Payload: raw})
	if err != nil || len(events) != 1 {
		t.Fatalf("%v %v", events, err)
	}
	a := events[0].Attributes
	if a["object_groups"] != "30" || a["qualifier"] != uint8(1) {
		t.Fatal(a)
	}
	if _, ok := a["object_count"]; ok {
		t.Fatal("invented unread count")
	}
	raw = linkFrame(0xc4, []byte{0xc0, 0xc0, FuncRead, 30})
	events, _ = NewDecoder().OnPacket(dnp3State(), &dpi.ParsedPacket{Payload: raw})
	if _, ok := events[0].Attributes["qualifier"]; ok {
		t.Fatal("invented unread qualifier")
	}
}
