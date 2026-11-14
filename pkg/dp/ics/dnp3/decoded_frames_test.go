// SPDX-License-Identifier: Apache-2.0
package dnp3

import (
	"errors"
	"fmt"
	"reflect"
	"testing"
	"time"

	"github.com/tonylturner/containd/pkg/dp/dpi"
)

func TestPairingDecodedFrames(t *testing.T) {
	t.Run("procedure-shapes", func(t *testing.T) {
		crob := []byte{12, 1, 0x17, 1, 7, 0x81, 2, 1, 0, 0, 0, 2, 0, 0, 0, 0}
		cases := []struct {
			name    string
			fc      byte
			objects []byte
		}{
			{"read-class0", 1, []byte{60, 1, 6}}, {"read-class1", 1, []byte{60, 2, 6}},
			{"read-class2", 1, []byte{60, 3, 6}}, {"read-class3", 1, []byte{60, 4, 6}},
			{"read-specific", 1, []byte{30, 1, 0, 2, 4}}, {"read-any-variation", 1, []byte{30, 0, 6}},
			{"write-time", 2, []byte{50, 1, 7, 1, 1, 2, 3, 4, 5, 6}}, {"write-iin", 2, []byte{80, 1, 0, 7, 7, 1}},
			{"select", 3, crob}, {"operate", 4, crob}, {"direct", 5, crob}, {"direct-no-ack", 6, crob},
			{"freeze-no-response", 8, []byte{20, 1, 6}}, {"freeze-clear-no-response", 10, []byte{20, 0, 6}},
			{"cold-restart", 13, nil}, {"warm-restart", 14, nil}, {"delay", 23, nil}, {"record-time", 24, nil},
			{"enable-unsolicited", 20, []byte{60, 2, 6, 60, 3, 6, 60, 4, 6}}, {"disable-unsolicited", 21, []byte{60, 2, 6}},
			{"confirm", 0, nil},
		}
		for _, tc := range cases {
			t.Run(tc.name, func(t *testing.T) {
				wire := appFrame(3, tc.fc, tc.objects...)
				frames := checkTypedSplits(t, dpi.ClientToServer, wire)
				s, e := PairingShape(frames[0].Unit.(*Unit))
				if e != nil || s.FunctionCode != tc.fc || s.Sequence != 3 || !s.FIR || !s.FIN || !s.Link.Master || s.Link.Confirmed {
					t.Fatal(s, e)
				}
				if tc.fc == 3 || tc.fc == 4 || tc.fc == 5 || tc.fc == 6 {
					p := s.Objects[0].Points[0]
					if *p.Index != 7 || p.CROB.Control != 0x81 || p.CROB.Count != 2 || p.CROB.OnTime != 1 || p.CROB.OffTime != 2 || p.CROB.Status != 0 {
						t.Fatal(p)
					}
				}
			})
		}
		// Every analog control encoding retains exact value bits and status.
		for variation, size := range map[byte]int{1: 4, 2: 2, 3: 4, 4: 8} {
			t.Run(fmt.Sprintf("analog-control-v%d", variation), func(t *testing.T) {
				value := make([]byte, size+1)
				value[0] = 0x34
				value[1] = 0x12
				objects := append([]byte{41, variation, 0x17, 1, 9}, value...)
				f := checkTypedSplits(t, dpi.ClientToServer, appFrame(3, 3, objects...))[0]
				s, e := PairingShape(f.Unit.(*Unit))
				if e != nil || s.Objects[0].Points[0].Value.Bits != 0x1234 || s.Objects[0].Points[0].Value.Status != 0 {
					t.Fatal(s, e)
				}
			})
		}
	})
	t.Run("response-families", func(t *testing.T) {
		for name, objects := range map[string][]byte{
			"read": {1, 2, 0, 4, 4, 0x81}, "write-status": nil,
			"control-echo":   {12, 1, 0x17, 1, 7, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0},
			"restart-coarse": {52, 1, 7, 1, 0x34, 0x12}, "restart-fine": {52, 2, 7, 1, 0x34, 0x12},
			"time": {50, 1, 7, 1, 1, 2, 3, 4, 5, 6}, "enable-disable-status": nil,
		} {
			t.Run(name, func(t *testing.T) {
				app := append([]byte{0xc3, 129, 0x80, 0x02}, objects...)
				f := checkTypedSplits(t, dpi.ServerToClient, linkFrame(0x44, append([]byte{0xc0}, app...)))[0]
				s, e := PairingShape(f.Unit.(*Unit))
				if e != nil || s.IIN1 != 0x80 || s.IIN2 != 2 || s.FunctionCode != 129 || s.Link.Master {
					t.Fatal(s, e)
				}
			})
		}
	})
	t.Run("transport-and-link-splits", func(t *testing.T) {
		app := []byte{0xc3, 3, 12, 1, 0x17, 1, 7, 0x81, 2, 1, 0, 0, 0, 2, 0, 0, 0, 0}
		for cut := 1; cut < len(app); cut++ {
			first := linkFrame(0xc4, append([]byte{0x7f}, app[:cut]...))
			last := linkFrame(0xc4, append([]byte{0x80}, app[cut:]...))
			f := checkTypedSplits(t, dpi.ClientToServer, concat(first, last))
			if len(f) != 2 || !f[0].Pending || f[0].Unit != nil || f[0].Coverage != nil || len(f[0].Events) != 0 {
				t.Fatal(f)
			}
			if _, e := PairingShape(f[1].Unit.(*Unit)); e != nil {
				t.Fatal(e)
			}
			want := []dpi.CoverageRange{{Start: 19, End: 19 + int64(len(first))}, {Start: 19 + int64(len(first)), End: 19 + int64(len(first)+len(last))}}
			if !reflect.DeepEqual(f[1].Coverage, want) || len(f[1].Events) != 1 {
				t.Fatal(f[1])
			}
		}
	})
	t.Run("discontiguous-multiple-completions", func(t *testing.T) {
		first := linkFrame(0xc4, []byte{0x40, 0xc3})
		other := buildTestFrame(11, 0xc4, 7, 8, []byte{0xc0, 0xc0, 1, 60, 1, 6})
		last := linkFrame(0xc4, []byte{0x81, 1, 60, 2, 6})
		f := checkTypedSplits(t, dpi.ClientToServer, concat(first, other, last, appFrame(4, 1, 60, 3, 6)))
		if len(f) != 4 || !f[0].Pending || len(f[1].Events) != 1 || len(f[2].Events) != 1 || len(f[3].Events) != 1 {
			t.Fatal(f)
		}
		want := []dpi.CoverageRange{{Start: 19, End: 19 + int64(len(first))}, {Start: 19 + int64(len(first)+len(other)), End: 19 + int64(len(first)+len(other)+len(last))}}
		if !reflect.DeepEqual(f[2].Coverage, want) {
			t.Fatal(f[2].Coverage, want)
		}
		if f[1].Unit.(*Unit).Link.Source != 8 || f[1].Unit.(*Unit).Link.Destination != 7 {
			t.Fatal(f[1].Unit)
		}
	})
	t.Run("link-control-zero-events", func(t *testing.T) {
		for _, control := range []byte{0xc0, 0xc1, 0xc2, 0xc9, 0, 1, 11, 15} {
			f := checkTypedSplits(t, dpi.ClientToServer, linkFrame(control, nil))[0]
			s, e := PairingShape(f.Unit.(*Unit))
			if e != nil || !s.LinkOnly || s.LinkFunction != control&15 || len(f.Events) != 0 {
				t.Fatal(s, e, f)
			}
		}
	})
	t.Run("application-fragments-and-confirm", func(t *testing.T) {
		var wire []byte
		for _, h := range []byte{0xae, 0x2f, 0x60} {
			wire = append(wire, linkFrame(0x44, []byte{0xc0, h, 129, 0, 0})...)
		}
		frames := checkTypedSplits(t, dpi.ServerToClient, wire)
		for i, f := range frames {
			s, e := PairingShape(f.Unit.(*Unit))
			if e != nil || s.Sequence != byte(14+i)&15 || s.FIR != (i == 0) || s.FIN != (i == 2) || !s.CON {
				t.Fatal(s, e)
			}
		}
		for _, h := range []byte{0xd0, 0xf1} {
			f := checkTypedSplits(t, dpi.ServerToClient, linkFrame(0x44, []byte{0xc0, h, 130, 0, 0, 1, 2, 0, 4, 4, 1}))[0]
			s, e := PairingShape(f.Unit.(*Unit))
			if e != nil || !s.UNS || s.FunctionCode != 130 {
				t.Fatal(s, e)
			}
		}
		// Confirm preserves UNS and sequence without a request or a response grant.
		f := checkTypedSplits(t, dpi.ClientToServer, linkFrame(0xc4, []byte{0xc0, 0xd3, 0}))[0]
		s, e := PairingShape(f.Unit.(*Unit))
		if e != nil || !s.UNS || s.Sequence != 3 {
			t.Fatal(s, e)
		}
	})
	t.Run("retry-exact-coverage-no-duplicate-application-event", func(t *testing.T) {
		first := linkFrame(0xc4, []byte{0x40, 0xc3})
		last := linkFrame(0xc4, []byte{0x81, 1, 60, 2, 6})
		f := checkTypedSplits(t, dpi.ClientToServer, concat(first, first, last))
		if len(f) != 3 || len(f[1].Events) != 1 || f[1].Events[0].Kind != "session" || len(f[2].Events) != 1 {
			t.Fatal(f)
		}
		if f[2].Unit.(*Unit).Objects[0].Group != 60 {
			t.Fatal(f[2].Unit)
		}
		if len(f[2].Coverage) != 3 || f[2].Coverage[1].Start != f[0].End || f[2].Coverage[1].End != f[1].End {
			t.Fatal(f[2])
		}
		if f[2].Events[0].Attributes["transport_segments"] != 2 || len(f[2].Events[0].Attributes["link_ranges"].([]LinkRange)) != 2 {
			t.Fatal("retry changed event projection", f[2].Events)
		}
		// A corrupted retry never makes a CRC-valid carrying unit, but the
		// legacy final event's CRC projection still describes logical segments.
		badRetry := append([]byte(nil), first...)
		badRetry[len(badRetry)-1] ^= 1
		corrupted := checkTypedSplits(t, dpi.ClientToServer, concat(first, badRetry, last))
		if _, e := PairingShape(corrupted[2].Unit.(*Unit)); e == nil {
			t.Fatal("retry CRC omitted from authority")
		}
		// Confirmed single- and multi-link procedures remain explicitly unsupported.
		for _, wire := range [][]byte{linkFrame(0xd3, []byte{0xc0, 0xc3, 1, 60, 2, 6}), concat(linkFrame(0xd3, []byte{0x40, 0xc3}), linkFrame(0xf3, []byte{0x81, 1, 60, 2, 6}))} {
			fs := checkTypedSplits(t, dpi.ClientToServer, wire)
			for _, f := range fs {
				if f.Pending {
					t.Fatal("confirmed data hidden as pending")
				}
				if _, e := PairingShape(f.Unit.(*Unit)); e == nil {
					t.Fatal("confirmed data enabled")
				}
			}
		}
	})
	t.Run("orphan-restart-conflict-expiry-unsupported", func(t *testing.T) {
		first := linkFrame(0x44, []byte{0x40, 0xc0, 129, 0, 0})
		for name, wire := range map[string][]byte{
			"orphan": linkFrame(0x44, []byte{0x81, 0}), "restart": concat(first, linkFrame(0x44, []byte{0xc0, 0xc1, 129, 0, 0})),
			"gap": concat(first, linkFrame(0x44, []byte{0x82})), "conflict": concat(first, linkFrame(0x44, []byte{0, 9})),
			"unknown-function": appFrame(0, 99), "unknown-group": appFrame(0, 1, 250, 1, 6), "bad-class": appFrame(0, 1, 60, 5, 6),
			"uns-mismatch": linkFrame(0x44, []byte{0xc0, 0xc0, 130, 0, 0}),
			"app-orphan":   linkFrame(0x44, []byte{0xc0, 0x40, 129, 0, 0}),
			"app-restart":  concat(linkFrame(0x44, []byte{0xc0, 0x80, 129, 0, 0}), linkFrame(0x44, []byte{0xc0, 0xc1, 129, 0, 0})),
			"short-header": linkFrame(0x44, []byte{0xc0, 0xc0}), "truncated-object": appFrame(0, 3, 12, 1, 7, 1, 1),
			"unknown-response-object": linkFrame(0x44, []byte{0xc0, 0xc0, 129, 0, 0, 250, 1, 6}),
			"link-payload":            linkFrame(0xc9, []byte{0xc0, 0xc0, 1}), "bad-link-control": linkFrame(0xc7, nil),
		} {
			t.Run(name, func(t *testing.T) {
				f := checkTypedSplits(t, dpi.ServerToClient, wire)
				last := f[len(f)-1]
				if last.Pending {
					t.Fatal("error hidden as pending")
				}
				if _, e := PairingShape(last.Unit.(*Unit)); e == nil {
					t.Fatal("normal completion of lost authority", last)
				}
			})
		}
		for _, lifetime := range []time.Duration{assemblyIdle, assemblyLifetime} {
			now := time.Unix(100, 0)
			d := NewDecoderWithClock(func() time.Time { return now })
			typedParse(t, d, 19, first)
			now = now.Add(lifetime)
			f := typedParse(t, d, 19+int64(len(first)), linkFrame(0x44, []byte{0x81}))[0]
			if f.Pending {
				t.Fatal(f)
			}
			if _, e := PairingShape(f.Unit.(*Unit)); e == nil {
				t.Fatal("expiry completed")
			}
		}
		// Progress inside the idle bound must not extend absolute lifetime.
		now := time.Unix(100, 0)
		d := NewDecoderWithClock(func() time.Time { return now })
		fs := typedParse(t, d, 19, first)
		base := fs[0].End
		for seq := byte(1); seq <= 3; seq++ {
			now = now.Add(20 * time.Second)
			h := seq
			if seq == 3 {
				h |= TransportFIN
			}
			fs = typedParse(t, d, base, linkFrame(0x44, []byte{h}))
			base = fs[0].End
			if seq < 3 && !fs[0].Pending {
				t.Fatal(fs)
			}
		}
		if fs[0].Pending {
			t.Fatal("absolute expiry hidden")
		}
		if _, e := PairingShape(fs[0].Unit.(*Unit)); e == nil {
			t.Fatal("absolute lifetime refreshed")
		}
		// A control change across transport segments cannot merge authority.
		fs = checkTypedSplits(t, dpi.ServerToClient, concat(first, linkFrame(0x53, []byte{0x81})))
		if _, e := PairingShape(fs[1].Unit.(*Unit)); e == nil {
			t.Fatal("control mismatch accepted")
		}
		if _, e := PairingShape(nil); !errors.Is(e, ErrIncompleteShape) {
			t.Fatal(e)
		}
	})
	t.Run("crc-framing-and-accounting", func(t *testing.T) {
		bad := append([]byte(nil), readFrame...)
		bad[len(bad)-1] ^= 1
		f := checkTypedSplits(t, dpi.ClientToServer, bad)[0]
		if _, e := PairingShape(f.Unit.(*Unit)); e == nil {
			t.Fatal("bad data CRC")
		}
		bad = append([]byte(nil), readFrame...)
		bad[8] ^= 1
		r, e := NewDecoder().ParseStream(dnp3State(), dpi.StreamView{Bytes: bad})
		if e == nil || len(r.Frames) != 0 {
			t.Fatal(r, e)
		}
		d := NewDecoder()
		first := linkFrame(0x44, []byte{0x40, 0xc0})
		typedParse(t, d, 19, first)
		r, e = d.ParseStream(dnp3State(), dpi.StreamView{Session: "typed", Dir: dpi.ServerToClient, Base: 19, Bytes: linkFrame(0x44, []byte{0x81, 129, 0, 0})})
		if e == nil || len(r.Frames) != 0 {
			t.Fatal("overlapping provenance published", r, e)
		}
		d.StreamEnded("typed", dpi.ServerToClient)
		if d.retainedBytes() != 0 {
			t.Fatal("retained credits leaked")
		}
	})
}
func typedParse(t *testing.T, d *Decoder, base int64, b []byte) []dpi.DecodedFrame {
	t.Helper()
	r, e := d.ParseStream(dnp3State(), dpi.StreamView{Session: "typed", Dir: dpi.ServerToClient, Base: base, Bytes: b})
	if e != nil {
		t.Fatal(e)
	}
	for _, f := range r.Frames {
		if e := dpi.ValidateDecodedFrame(f); e != nil {
			t.Fatal(e)
		}
		if !f.Pending && f.Unit == nil {
			t.Fatal(f)
		}
	}
	return r.Frames
}
func checkTypedSplits(t *testing.T, dir dpi.StreamDir, wire []byte) []dpi.DecodedFrame {
	t.Helper()
	parse := func(d *Decoder, base int64, b []byte) dpi.StreamResult {
		r, e := d.ParseStream(dnp3State(), dpi.StreamView{Session: "typed", Dir: dir, Base: base, Bytes: b})
		if e != nil {
			t.Fatal(e)
		}
		for _, f := range r.Frames {
			if e := dpi.ValidateDecodedFrame(f); e != nil {
				t.Fatal(e)
			}
			if !f.Pending && f.Unit == nil {
				t.Fatal(f)
			}
		}
		return r
	}
	owned := append([]byte(nil), wire...)
	d := NewDecoder()
	whole := parse(d, 19, owned)
	// Compare typed units independently of event JSON (private validation errors
	// and hidden typed object values are part of reflect.DeepEqual below).
	snapshots := make([]string, len(whole.Frames))
	for i, f := range whole.Frames {
		snapshots[i] = fmt.Sprintf("%#v/%#v", f.Unit, f.Coverage)
	}
	for i := range owned {
		owned[i] = 0xee
	}
	d.StreamEnded("typed", dir)
	for i, f := range whole.Frames {
		if snapshots[i] != fmt.Sprintf("%#v/%#v", f.Unit, f.Coverage) {
			t.Fatal("result aliases refunded assembly")
		}
	}
	if d.retainedBytes() != 0 {
		t.Fatal("leaked decoder state")
	}
	for cut := 0; cut <= len(wire); cut++ {
		d := NewDecoder()
		head := parse(d, 19, wire[:cut])
		tail := parse(d, 19+int64(head.Consumed), wire[head.Consumed:])
		if !reflect.DeepEqual(append(head.Frames, tail.Frames...), whole.Frames) {
			t.Fatalf("cut %d changed typed frames", cut)
		}
		d.StreamEnded("typed", dir)
		if d.retainedBytes() != 0 {
			t.Fatal("split leaked credit")
		}
	}
	return whole.Frames
}
