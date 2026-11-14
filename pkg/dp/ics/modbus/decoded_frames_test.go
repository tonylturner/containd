// SPDX-License-Identifier: Apache-2.0
package modbus

import (
	"encoding/binary"
	"errors"
	"fmt"
	"reflect"
	"testing"

	"github.com/tonylturner/containd/pkg/dp/dpi"
)

func shapeADU(fc byte, p ...byte) []byte {
	b := []byte{0x12, 0x34, 0, 0, 0, 0, 7, fc}
	b = append(b, p...)
	binary.BigEndian.PutUint16(b[4:6], uint16(len(b)-6))
	return b
}
func TestPairingDecodedFrames(t *testing.T) {
	cases := []struct {
		fc                byte
		request, response []byte
	}{
		{1, []byte{0, 10, 0, 9}, []byte{2, 1, 0}},
		{2, []byte{0, 10, 0, 9}, []byte{2, 1, 0}},
		{3, []byte{0, 10, 0, 2}, []byte{4, 0, 3, 0, 4}},
		{4, []byte{0, 10, 0, 2}, []byte{4, 0, 3, 0, 4}},
		{5, []byte{0, 10, 0xff, 0}, []byte{0, 10, 0xff, 0}},
		{6, []byte{0, 10, 0x12, 0x34}, []byte{0, 10, 0x12, 0x34}},
		{15, []byte{0, 10, 0, 9, 2, 1, 0}, []byte{0, 10, 0, 9}},
		{16, []byte{0, 10, 0, 2, 4, 0, 3, 0, 4}, []byte{0, 10, 0, 2}},
		{22, []byte{0, 10, 0x12, 0x34, 0x56, 0x78}, []byte{0, 10, 0x12, 0x34, 0x56, 0x78}},
		{23, []byte{0, 10, 0, 2, 0, 20, 0, 1, 2, 0, 9}, []byte{4, 0, 3, 0, 4}},
	}
	for _, tc := range cases {
		for _, response := range []bool{false, true} {
			t.Run(fmt.Sprintf("fc%d/response%t", tc.fc, response), func(t *testing.T) {
				dir := dpi.ClientToServer
				p := tc.request
				if response {
					dir = dpi.ServerToClient
					p = tc.response
				}
				wire := shapeADU(tc.fc, p...)
				// Coalescing and an incomplete third ADU exercise prefix trimming at
				// every byte, including through the MBAP length and PDU byte count.
				stream := concat(wire, wire, wire[:len(wire)-1])
				frames := checkTypedSplits(t, dir, stream)
				if len(frames) != 2 {
					t.Fatal(frames)
				}
				s, err := PairingShape(frames[0].Unit.(*Unit))
				if err != nil || s.TransactionID != 0x1234 || s.UnitID != 7 || s.FunctionCode != tc.fc || s.Response != response {
					t.Fatal(s, err)
				}
				if !response && len(s.Spans) == 0 {
					t.Fatal("request lost spans", s)
				}
				switch tc.fc {
				case 1, 2, 3, 4:
					if response && (s.Address != 0 || s.Quantity != 0 || len(s.Spans) != 0) {
						t.Fatal("fabricated response provenance", s)
					}
				case 5, 6:
					if s.Address != 10 || s.Value != be16(tc.request, 2) {
						t.Fatal(s)
					}
				case 15, 16:
					if s.Address != 10 || s.Quantity != be16(tc.request, 2) {
						t.Fatal(s)
					}
				case 22:
					if s.AndMask != 0x1234 || s.OrMask != 0x5678 {
						t.Fatal(s)
					}
				case 23:
					if !response && (s.ReadAddress != 10 || s.ReadQuantity != 2 || s.WriteAddress != 20 || s.WriteQuantity != 1 || len(s.Spans) != 2 || s.Values[0] != 9) {
						t.Fatal(s)
					}
				}
			})
		}
		t.Run(fmt.Sprintf("exceptions/fc%d", tc.fc), func(t *testing.T) {
			for _, code := range []byte{1, 2, 3, 4, 5, 6, 8, 10, 11} {
				f := checkTypedSplits(t, dpi.ServerToClient, shapeADU(tc.fc|128, code))[0]
				s, err := PairingShape(f.Unit.(*Unit))
				if err != nil || !s.Exception || s.ExceptionCode != code || s.FunctionCode != tc.fc {
					t.Fatal(s, err)
				}
			}
		})
	}
	t.Run("unsupported-and-invalid", func(t *testing.T) {
		badUnit := shapeADU(3, 0, 0, 0, 1)
		badUnit[6] = 0
		badPID := shapeADU(3, 0, 0, 0, 1)
		badPID[3] = 1
		for name, wire := range map[string][]byte{
			"diagnostics": shapeADU(8, 0, 0, 0, 0), "mei": shapeADU(43, 14, 1, 0), "unknown": shapeADU(100),
			"broadcast": badUnit, "pid": badPID, "short": shapeADU(3, 0), "zero-quantity": shapeADU(3, 0, 0, 0, 0),
			"long-span": shapeADU(3, 255, 255, 0, 2), "bad-coil": shapeADU(5, 0, 0, 0, 1),
			"byte-count": shapeADU(16, 0, 0, 0, 2, 2, 0, 0), "fc23-write-count": shapeADU(23, 0, 0, 0, 1, 0, 0, 0, 0, 0),
		} {
			t.Run(name, func(t *testing.T) {
				f := checkTypedSplits(t, dpi.ClientToServer, wire)[0]
				if _, err := PairingShape(f.Unit.(*Unit)); err == nil {
					t.Fatal("accepted unsupported/invalid shape", f.Unit)
				}
			})
		}
		for _, wire := range [][]byte{shapeADU(0x83, 0), shapeADU(0x83, 7), shapeADU(0x83, 1, 0), shapeADU(3, 3, 1, 2, 3)} {
			f := checkTypedSplits(t, dpi.ServerToClient, wire)[0]
			if _, err := PairingShape(f.Unit.(*Unit)); err == nil {
				t.Fatal("accepted bad reply", f.Unit)
			}
		}
		if _, err := PairingShape(nil); !errors.Is(err, ErrIncompleteShape) {
			t.Fatal(err)
		}
	})
	t.Run("frame-errors", func(t *testing.T) {
		wire := concat(readADU, []byte{0, 0, 0, 0, 0, 1})
		r, err := NewDecoder().ParseStream(modbusState(), dpi.StreamView{Bytes: wire})
		if err == nil || len(r.Frames) != 1 {
			t.Fatal(r, err)
		}
		if err := dpi.ValidateDecodedFrame(r.Frames[0]); err != nil {
			t.Fatal(err)
		}
		r, err = NewDecoder().ParseStream(modbusState(), dpi.StreamView{Base: -1, Bytes: readADU})
		if err == nil || len(r.Frames) != 0 {
			t.Fatal("published invalid range", r, err)
		}
	})
}
func checkTypedSplits(t *testing.T, dir dpi.StreamDir, wire []byte) []dpi.DecodedFrame {
	t.Helper()
	parse := func(base int64, b []byte) dpi.StreamResult {
		r, err := NewDecoder().ParseStream(modbusState(), dpi.StreamView{Session: "typed", Dir: dir, Base: base, Bytes: b})
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
	whole := parse(31, owned)
	before := fmt.Sprintf("%#v", whole.Frames[0].Unit.(*Unit).PairShape)
	for i := range owned {
		owned[i] = 0xee
	}
	if fmt.Sprintf("%#v", whole.Frames[0].Unit.(*Unit).PairShape) != before {
		t.Fatal("unit aliases stream")
	}
	for cut := 0; cut <= len(wire); cut++ {
		head := parse(31, wire[:cut])
		tail := parse(31+int64(head.Consumed), wire[head.Consumed:])
		got := append(head.Frames, tail.Frames...)
		if !reflect.DeepEqual(got, whole.Frames) {
			t.Fatalf("cut %d changed typed frames", cut)
		}
	}
	return whole.Frames
}
