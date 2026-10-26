// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

package iec104

import (
	"encoding/binary"
	"testing"

	"github.com/tonylturner/containd/pkg/dp/dpi"
	"github.com/tonylturner/containd/pkg/dp/ics/eventfields"
	"github.com/tonylturner/containd/pkg/dp/ics/eventfields/decodertest"
)

// Non-finite short floats: the standard does not forbid NaN or
// infinities in R32, so such an object keeps its kind and every other
// attribute, omits value and sets value_invalid.

// nonFinite holds R32-IEEE STD 754 bit patterns that have no JSON number.
var nonFinite = []struct {
	name string
	bits uint32
}{
	{"+Inf", 0x7F800000},
	{"-Inf", 0xFF800000},
	{"quiet NaN", 0x7FC00000},
	{"signalling NaN", 0x7FA00001}, // quiet bit 22 clear, mantissa non-zero
	{"negative signalling NaN", 0xFF800001},
}

func r32(bits uint32) []byte { return binary.LittleEndian.AppendUint32(nil, bits) }

func TestNonFiniteShortFloat(t *testing.T) {
	noTime := []string{eventfields.KeySourceTime, eventfields.KeyTimeValid, eventfields.KeyTimeSummer}
	for _, nf := range nonFinite {
		cases := []struct {
			name     string
			dir      dpi.StreamDir
			asdu     []byte
			kind     string
			want     objWant
			absent   []string
			safeRead bool
		}{
			{"13 M_ME_NC_1", srv, asdu(13, 1, cotSpont, 0, 1, cat(ioa(1001), r32(nf.bits), []byte{0x90})...), eventfields.KindResponse,
				objWant{eventfields.KeyIOA: uint32(1001), eventfields.KeyQuality: uint8(0x90), eventfields.KeyClass: ClassMonitor, eventfields.KeyIsWrite: false},
				append([]string{eventfields.KeySelect, eventfields.KeyQualifier}, noTime...), true},
			{"36 M_ME_TF_1", srv, asdu(36, 1, cotSpont, 0, 1, cat(ioa(1002), r32(nf.bits), []byte{0x90}, courseTime)...), eventfields.KindResponse,
				objWant{
					eventfields.KeyIOA: uint32(1002), eventfields.KeyQuality: uint8(0x90),
					eventfields.KeyClass: ClassMonitor, eventfields.KeyIsWrite: false,
					eventfields.KeySourceTime: "2026-11-07T09:15:02.345", eventfields.KeyTimeValid: true, eventfields.KeyTimeSummer: false,
				},
				[]string{eventfields.KeySelect, eventfields.KeyQualifier}, true},
			{"50 C_SE_NC_1 select", cli, asdu(50, 1, cotAct, 0, 1, cat(ioa(7003), r32(nf.bits), []byte{0x85})...), eventfields.KindRequest,
				objWant{eventfields.KeyIOA: uint32(7003), eventfields.KeySelect: true, eventfields.KeyQualifier: uint8(5), eventfields.KeyClass: ClassControl, eventfields.KeyIsWrite: true},
				append([]string{eventfields.KeyQuality}, noTime...), false},
			{"50 C_SE_NC_1 confirmation", srv, asdu(50, 1, cotActCon, 0, 1, cat(ioa(7003), r32(nf.bits), []byte{0x05})...), eventfields.KindResponse,
				objWant{eventfields.KeyIOA: uint32(7003), eventfields.KeySelect: false, eventfields.KeyQualifier: uint8(5), eventfields.KeyClass: ClassControl, eventfields.KeyIsWrite: false},
				append([]string{eventfields.KeyQuality}, noTime...), false},
			{"63 C_SE_TC_1 execute", cli, asdu(63, 1, cotAct, 0, 1, cat(ioa(7006), r32(nf.bits), []byte{0x02}, courseTime)...), eventfields.KindRequest,
				objWant{
					eventfields.KeyIOA: uint32(7006), eventfields.KeySelect: false, eventfields.KeyQualifier: uint8(2),
					eventfields.KeyClass: ClassControl, eventfields.KeyIsWrite: true,
					eventfields.KeySourceTime: "2026-11-07T09:15:02.345", eventfields.KeyTimeValid: true, eventfields.KeyTimeSummer: false,
				},
				[]string{eventfields.KeyQuality}, false},
		}
		for _, tc := range cases {
			label := tc.name + " " + nf.name
			res := parseOne(t, tc.dir, iFrame(2, 3, tc.asdu))
			checkEvents(t, res)
			evs := events(res)
			if len(evs) != 1 {
				t.Fatalf("%s: %d events", label, len(evs))
			}
			if evs[0].Kind != tc.kind {
				t.Errorf("%s: kind %s (%v), want %s", label, evs[0].Kind, evs[0].Attributes[eventfields.KeyError], tc.kind)
			}
			tc.want[eventfields.KeyValueInvalid] = true
			tc.want[eventfields.KeyTypeID] = tc.asdu[0]
			checkAttrs(t, label, evs[0].Attributes, tc.want, append(tc.absent, eventfields.KeyValue, eventfields.KeyError)...)
			for form, a := range decodertest.Forms(t, evs[0].Attributes) {
				if v, ok := eventfields.Bool(a, eventfields.KeyValueInvalid); !ok || !v {
					t.Errorf("%s %s: value_invalid = %v/%v", label, form, v, ok)
				}
				if _, ok := eventfields.Float64(a, eventfields.KeyValue); ok {
					t.Errorf("%s %s: value present", label, form)
				}
				if v, ok := eventfields.Uint32(a, eventfields.KeyIOA); !ok || v != tc.want[eventfields.KeyIOA] {
					t.Errorf("%s %s: ioa = %d/%v", label, form, v, ok)
				}
				if got := SafeRead(a); got != tc.safeRead {
					t.Errorf("%s %s: SafeRead = %v, want %v", label, form, got, tc.safeRead)
				}
			}
		}
	}
}

// Only the non-finite objects of an ASDU are flagged; their finite siblings
// keep value and never carry value_invalid.
func TestNonFiniteShortFloatSiblings(t *testing.T) {
	sq := iFrame(0, 0, asdu(13, vsqSQ|3, cotInrogen, 0, 1, cat(ioa(100), f32(1.5), []byte{0}, r32(0x7FC00000), []byte{0x80}, f32(-2), []byte{0})...))
	perIOA := iFrame(1, 0, asdu(13, 2, cotSpont, 0, 1, cat(ioa(9), r32(0xFF800000), []byte{0}, ioa(4), f32(0), []byte{0x10})...))
	res := parseOne(t, srv, cat(sq, perIOA))
	checkEvents(t, res)
	evs := events(res)
	if len(evs) != 5 {
		t.Fatalf("%d events", len(evs))
	}
	want := []struct {
		obj    objWant
		absent string
	}{
		{objWant{eventfields.KeyIOA: uint32(100), eventfields.KeyValue: float32(1.5)}, eventfields.KeyValueInvalid},
		{objWant{eventfields.KeyIOA: uint32(101), eventfields.KeyValueInvalid: true, eventfields.KeyQuality: uint8(0x80)}, eventfields.KeyValue},
		{objWant{eventfields.KeyIOA: uint32(102), eventfields.KeyValue: float32(-2)}, eventfields.KeyValueInvalid},
		{objWant{eventfields.KeyIOA: uint32(9), eventfields.KeyValueInvalid: true}, eventfields.KeyValue},
		{objWant{eventfields.KeyIOA: uint32(4), eventfields.KeyValue: float32(0), eventfields.KeyQuality: uint8(0x10)}, eventfields.KeyValueInvalid},
	}
	for i, ev := range evs {
		if ev.Kind != eventfields.KindResponse {
			t.Errorf("object %d: kind %s", i, ev.Kind)
		}
		checkAttrs(t, "sibling", ev.Attributes, want[i].obj, want[i].absent)
	}
}
