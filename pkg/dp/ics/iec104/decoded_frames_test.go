// SPDX-License-Identifier: Apache-2.0
package iec104

import (
	"errors"
	"fmt"
	"reflect"
	"testing"

	"github.com/tonylturner/containd/pkg/dp/dpi"
)

func TestPairingDecodedFrames(t *testing.T) {
	for typ, d := range descriptors {
		var element []byte
		switch d.elem {
		case elemSCO, elemDCO, elemRCO:
			element = []byte{0x85}
		case elemNVAQOS, elemSVAQOS:
			element = []byte{0x34, 0x12, 0x82}
		case elemFloatQOS:
			element = cat(r32(0x7fa01234), []byte{0x82})
		case elemBSI:
			element = []byte{0x12, 0x34, 0x56, 0x78}
		case elemQOI:
			element = []byte{20}
		case elemQCC:
			element = []byte{5}
		case elemQRP:
			element = []byte{1}
		case elemTSC:
			element = []byte{0x34, 0x12}
		default:
			element = make([]byte, elementSize[d.elem])
		}
		if d.timed {
			element = cat(element, courseTime)
		}
		causes := []byte{6, 7, 10}
		address := uint32(0x123456)
		switch {
		case d.class == ClassMonitor:
			causes = []byte{1, 2, 3, 5, 20, 21, 36, 37, 41}
		case typ == 70:
			causes = []byte{4}
			address = 0
		case typ == 102:
			causes = []byte{5}
		case typ == 103 || typ == 105 || typ == 107:
			causes = []byte{6, 7}
			address = 0
		case typ == 100 || typ == 101:
			address = 0
		}
		for _, cause := range causes {
			t.Run(fmt.Sprintf("type%d/cot%d", typ, cause), func(t *testing.T) {
				dir := dpi.ServerToClient
				if cause == 6 || typ == 102 {
					dir = dpi.ClientToServer
				}
				wire := iFrame(123, 456, asdu(typ, 1, cause, 9, 23, cat(ioa(address), element)...))
				frames := checkTypedSplits(t, dir, cat(wire, wire, wire[:len(wire)-1]))
				if len(frames) != 2 {
					t.Fatal(frames)
				}
				s, err := PairingShape(frames[0].Unit.(*Unit))
				if err != nil || s.Format != "I" || s.TypeID != typ || s.Cause != cause || s.CA != 23 || s.Originator != 9 || s.SendSequence != 123 || s.ReceiveSequence != 456 || len(s.Objects) != 1 || s.Objects[0].IOA != address {
					t.Fatal(s, err)
				}
				o := s.Objects[0]
				switch d.elem {
				case elemSCO, elemDCO, elemRCO:
					if o.ValueBits != 1 || o.Qualifier != 1 || !o.Select {
						t.Fatal(o)
					}
				case elemNVAQOS, elemSVAQOS:
					if o.ValueBits != 0x1234 || o.Qualifier != 2 || !o.Select {
						t.Fatal(o)
					}
				case elemFloatQOS:
					if o.ValueBits != 0x7fa01234 || o.Qualifier != 2 || !o.Select {
						t.Fatal(o)
					}
				case elemBSI:
					if o.ValueBits != 0x78563412 {
						t.Fatal(o)
					}
				case elemTSC:
					if o.TestSequence != 0x1234 {
						t.Fatal(o)
					}
				}
				if d.timed && !reflect.DeepEqual(o.Time[:], courseTime) {
					t.Fatal("lost exact time", o)
				}
				if cause == 7 || cause == 10 {
					neg := append([]byte(nil), wire...)
					neg[8] |= 0xc0
					f := checkTypedSplits(t, dir, neg)[0]
					ns, e := PairingShape(f.Unit.(*Unit))
					if e != nil || !ns.Negative || !ns.Test {
						t.Fatal(ns, e)
					}
				}
			})
		}
	}
	t.Run("session-controls", func(t *testing.T) {
		controls := [][]byte{sFrame(234)}
		for fn := range uFunctions {
			controls = append(controls, uFrame(fn))
		}
		for _, wire := range controls {
			for _, dir := range []dpi.StreamDir{dpi.ClientToServer, dpi.ServerToClient} {
				f := checkTypedSplits(t, dir, wire)[0]
				if _, err := PairingShape(f.Unit.(*Unit)); err != nil {
					t.Fatal(err)
				}
			}
		}
	})
	t.Run("typed-object-tree", func(t *testing.T) {
		wire := iFrame(0, 0, asdu(13, 0x83, 20, 0, 1, cat(ioa(100), f32(1.5), []byte{0x80}, r32(0x7fa01234), []byte{0x90}, f32(-2), []byte{0xa0})...))
		f := checkTypedSplits(t, dpi.ServerToClient, wire)[0]
		s, e := PairingShape(f.Unit.(*Unit))
		if e != nil || !s.SQ || len(s.Objects) != 3 || s.Objects[1].IOA != 101 || s.Objects[1].ValueBits != 0x7fa01234 || s.Objects[1].Quality != 0x90 {
			t.Fatal(s, e)
		}
		f.Events[1].Attributes["value"] = 99
		if s.Objects[1].ValueBits != 0x7fa01234 {
			t.Fatal("event mutated unit")
		}
	})
	t.Run("apci-reserved-observational", func(t *testing.T) {
		wire := iFrame(0, 0, asdu(100, 1, 6, 0, 1, 0, 0, 0, 20))
		wire[4] |= 0x01 // reserved bit of receive control octet 3
		f := checkTypedSplits(t, dpi.ClientToServer, wire)[0]
		if s, err := PairingShape(f.Unit.(*Unit)); err != nil || s.TypeID != 100 {
			t.Fatalf("reserved APCI bit changed pairing shape: %+v %v", s, err)
		}
	})
	t.Run("unsupported-errors", func(t *testing.T) {
		for _, wire := range [][]byte{
			iFrame(0, 0, asdu(200, 1, 3, 0, 1, 0, 0, 0)),
			iFrame(0, 0, asdu(45, 1, 3, 0, 1, 0, 0, 0, 1)),
			iFrame(0, 0, asdu(1, 1, 7, 0, 1, 0, 0, 0, 1)),
			iFrame(0, 0, asdu(70, 1, 3, 0, 1, 0, 0, 0, 0)),
			iFrame(0, 0, asdu(100, 1, 7, 0, 1, 0, 0, 0, 19)),
			iFrame(0, 0, asdu(101, 1, 7, 0, 1, 0, 0, 0, 6)),
			iFrame(0, 0, asdu(105, 1, 7, 0, 1, 0, 0, 0, 3)),
			iFrame(0, 0, asdu(103, 1, 10, 0, 1, cat(ioa(0), courseTime)...)),
			iFrame(0, 0, asdu(102, 1, 6, 0, 1, 0, 0, 0)),
			iFrame(0, 0, asdu(45, 1, 7, 0, 1, 0, 0, 0, 3)),
			iFrame(0, 0, asdu(1, 1, 3, 0, BroadcastCA, 0, 0, 0, 1)),
			iFrame(0, 0, asdu(1, 1, 3, 0, 0, 0, 0, 0, 1)),
			iFrame(0, 0, asdu(45, 2, 7, 0, 1, 0, 0, 0, 1, 1, 0, 0, 1)),
			iFrame(0, 0, asdu(45, 1, 7, 0, 1, 0, 0, 0)),
			iFrame(0, 0, nil), uFrame(0xff), {0x68, 5, 1, 0, 0, 0, 0},
		} {
			f := checkTypedSplits(t, dpi.ServerToClient, wire)[0]
			if _, err := PairingShape(f.Unit.(*Unit)); err == nil {
				t.Fatalf("accepted %x", wire)
			}
		}
		for _, fx := range loadFixtures(t) {
			if fx.kinds == nil {
				continue
			}
			f := checkTypedSplits(t, fx.dir, fx.bytes)[0]
			if f.Unit == nil {
				t.Fatal(fx.name, "lost malformed/unsupported unit")
			}
		}
		if _, err := PairingShape(nil); !errors.Is(err, ErrIncompleteShape) {
			t.Fatal(err)
		}
		r, err := NewDecoder().ParseStream(iecState(), view(dpi.ServerToClient, -1, sFrame(0)))
		if err == nil || len(r.Frames) != 0 {
			t.Fatal("published bad offset", r, err)
		}
		r, err = NewDecoder().ParseStream(iecState(), view(dpi.ServerToClient, 0, cat(sFrame(0), []byte{0x69})))
		if err == nil || len(r.Frames) != 1 {
			t.Fatal(r, err)
		}
		if err := dpi.ValidateDecodedFrame(r.Frames[0]); err != nil {
			t.Fatal(err)
		}
	})
}
func checkTypedSplits(t *testing.T, dir dpi.StreamDir, wire []byte) []dpi.DecodedFrame {
	t.Helper()
	parse := func(base int64, b []byte) dpi.StreamResult {
		r, err := NewDecoder().ParseStream(iecState(), view(dir, base, b))
		if err != nil {
			t.Fatal(err)
		}
		for _, f := range r.Frames {
			if err := dpi.ValidateDecodedFrame(f); err != nil {
				t.Fatal(err)
			}
			if f.Unit == nil || f.Pending || f.Coverage != nil {
				t.Fatal(f)
			}
		}
		return r
	}
	owned := append([]byte(nil), wire...)
	whole := parse(17, owned)
	before := fmt.Sprintf("%#v", whole.Frames[0].Unit.(*Unit).PairShape)
	for i := range owned {
		owned[i] = 0xee
	}
	if fmt.Sprintf("%#v", whole.Frames[0].Unit.(*Unit).PairShape) != before {
		t.Fatal("unit aliases stream")
	}
	for cut := 0; cut <= len(wire); cut++ {
		head := parse(17, wire[:cut])
		tail := parse(17+int64(head.Consumed), wire[head.Consumed:])
		if !reflect.DeepEqual(append(head.Frames, tail.Frames...), whole.Frames) {
			t.Fatalf("cut %d changed typed frames", cut)
		}
	}
	return whole.Frames
}
