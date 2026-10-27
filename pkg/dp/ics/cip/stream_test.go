// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 containd Authors

package cip

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"reflect"
	"testing"
	"time"

	"github.com/tonylturner/containd/pkg/dp/dpi"
	"github.com/tonylturner/containd/pkg/dp/flow"
	"github.com/tonylturner/containd/pkg/dp/ics/eventfields/decodertest"
)

func streamFixtures() []struct {
	name   string
	raw    []byte
	events int
} {
	return []struct {
		name   string
		raw    []byte
		events int
	}{
		{"session", buildEIPHeader(0x65, 1, []byte{1, 0, 0, 0}), 1},
		{"read", buildEIPHeader(0x6f, 2, buildSendRRDataPayload(0x4c, 3, []byte{0x20, 4, 0x24, 1, 0x30, 3})), 1},
		{"write", buildEIPHeader(0x6f, 3, buildSendRRDataPayload(0x4d, 1, []byte{0x20, 4})), 1},
		{"response", buildEIPHeader(0x6f, 4, buildSendRRDataPayload(0xcc, 0, nil)), 1},
		{"connected", buildEIPHeader(0x70, 5, buildCPFItems(
			cpfTestItem{0x00a1, []byte{1, 0, 0, 0}},
			cpfTestItem{0x00b1, []byte{1, 0, 0x4c, 0}},
		)), 1},
		{"MSP", buildEIPHeader(0x6f, 6, buildSendRRDataPayloadWithData(0x0a, 0, nil,
			[]byte{2, 0, 6, 0, 10, 0, 0x4c, 1, 0x20, 4, 0x4d, 1, 0x20, 4})), 3},
		{"unknown command", buildEIPHeader(0xffff, 7, []byte{1, 2, 3}), 1},
		{"malformed CPF", buildEIPHeader(0x6f, 8, []byte{0}), 1},
	}
}

func cipState() *flow.State {
	return flow.NewState(keyFor("10.0.0.1", "10.0.0.2", 12345, 44818, 6), time.Now())
}

func assertSameEvents(t testing.TB, got, want []dpi.Event) {
	t.Helper()
	if len(got) != len(want) {
		t.Fatalf("events = %d, want %d", len(got), len(want))
	}
	for i := range got {
		g, w := got[i], want[i]
		if g.Timestamp.IsZero() || w.Timestamp.IsZero() {
			t.Fatal("missing event timestamp")
		}
		g.Timestamp, w.Timestamp = time.Time{}, time.Time{}
		if !reflect.DeepEqual(g, w) {
			t.Fatalf("event %d = %+v, want %+v", i, g, w)
		}
	}
}

func TestParseStreamSplitAtEveryByte(t *testing.T) {
	for _, fixture := range streamFixtures() {
		t.Run(fixture.name, func(t *testing.T) {
			d, st := NewDecoder(), cipState()
			view := dpi.StreamView{Session: "s", Base: 123, Bytes: fixture.raw}
			whole, err := decodertest.CheckStream(t, d, st, view)
			if err != nil || len(whole.Frames) != 1 || len(whole.Frames[0].Events) != fixture.events {
				t.Fatalf("whole = %+v, err = %v", whole, err)
			}
			packetEvents, err := d.OnPacket(st, &dpi.ParsedPacket{Payload: fixture.raw})
			if err != nil {
				t.Fatal(err)
			}
			assertSameEvents(t, whole.Frames[0].Events, packetEvents)
			decodertest.CheckSplits(t, d, st, view)
		})
	}
}

func TestParseStreamCoalescedAndIncompleteTail(t *testing.T) {
	fixtures := streamFixtures()
	for _, count := range []int{2, 3} {
		t.Run(fmt.Sprint(count), func(t *testing.T) {
			var raw []byte
			for _, f := range fixtures[:count] {
				raw = append(raw, f.raw...)
			}
			prefixLen := len(raw)
			for tailLen := 0; tailLen < len(fixtures[3].raw); tailLen++ {
				stream := append(bytes.Clone(raw), fixtures[3].raw[:tailLen]...)
				res, err := decodertest.CheckStream(t, NewDecoder(), cipState(), dpi.StreamView{Base: 45, Bytes: stream})
				if err != nil || len(res.Frames) != count || res.Consumed != prefixLen || res.NeedMore != (tailLen > 0) {
					t.Fatalf("tail %d: result = %+v, err = %v", tailLen, res, err)
				}
				for i, frame := range res.Frames {
					assertEncapsulation(t, frame.Events[0].Attributes, binary.LittleEndian.Uint16(fixtures[i].raw), uint32(i+1))
				}
			}
			decodertest.CheckSplits(t, NewDecoder(), cipState(), dpi.StreamView{Base: 45, Bytes: raw})
		})
	}
}

func TestParseStreamLengthBound(t *testing.T) {
	const bound = 64 * 1024
	d, st := NewDecoder(), cipState()
	for _, size := range []int{eipHeaderSize, bound, bound + 1, eipHeaderSize + 65535} {
		t.Run(fmt.Sprint(size), func(t *testing.T) {
			raw := buildEIPHeader(0xffff, 1, make([]byte, size-eipHeaderSize))
			res, err := decodertest.CheckStream(t, d, st, dpi.StreamView{Base: 99, Bytes: raw})
			if size <= bound {
				if err != nil || res.Consumed != size || len(res.Frames) != 1 {
					t.Fatalf("frameable length: %+v, %v", res, err)
				}
				return
			}
			var fe *dpi.FrameError
			if !errors.As(err, &fe) || fe.Offset != 99 || fe.Event.FlowID != st.Key.Hash() || fe.Event.Attributes["error"] == "" {
				t.Fatalf("unframeable length: %+v, %v", res, err)
			}
			if got := fe.Event.Attributes["raw_hex"].(string); len(got) != 1024 {
				t.Fatalf("raw hex length = %d, want 1024", len(got))
			}
			// No body is needed to reject an impossible declared length.
			good := streamFixtures()[0].raw
			prefix := append(bytes.Clone(good), raw[:eipHeaderSize]...)
			res, err = decodertest.CheckStream(t, d, st, dpi.StreamView{Base: 99, Bytes: prefix})
			if !errors.As(err, &fe) || res.Consumed != len(good) || len(res.Frames) != 1 || fe.Offset != 99+int64(len(good)) {
				t.Fatalf("valid prefix before bad length: %+v, %v", res, err)
			}
		})
	}
}

func cipSegment(seq uint32, payload []byte) *dpi.ParsedPacket {
	return &dpi.ParsedPacket{
		Proto: "tcp", SrcPort: 12345, DstPort: 44818,
		TCPSeq: seq, TCPSeqValid: true, Payload: payload,
	}
}

func TestManagerReassemblesAndCountsRetransmissionOnce(t *testing.T) {
	var raw []byte
	var want []dpi.Event
	for _, f := range streamFixtures() {
		raw = append(raw, f.raw...)
		evs, err := NewDecoder().OnPacket(cipState(), &dpi.ParsedPacket{Payload: f.raw})
		if err != nil {
			t.Fatal(err)
		}
		want = append(want, evs...)
	}
	for cut := 1; cut < len(raw); cut++ {
		mgr, st := dpi.NewManager(NewDecoder()), cipState()
		first := mgr.Inspect(st, cipSegment(100, raw[:cut]))
		duplicateHead := mgr.Inspect(st, cipSegment(100, raw[:cut]))
		second := mgr.Inspect(st, cipSegment(100+uint32(cut), raw[cut:]))
		duplicateAll := mgr.Inspect(st, cipSegment(100, raw))
		for _, r := range []dpi.InspectResult{first, duplicateHead, second, duplicateAll} {
			if r.Err != nil || !r.Framed || r.Proto != "cip" {
				t.Fatalf("cut %d: %+v", cut, r)
			}
		}
		if len(duplicateHead.Events) != 0 || len(duplicateAll.Events) != 0 || second.NeedMore {
			t.Fatalf("cut %d: retransmission emitted events or incomplete final parse", cut)
		}
		assertSameEvents(t, append(first.Events, second.Events...), want)
		frames := append(first.Frames, second.Frames...)
		if len(frames) != len(streamFixtures()) || frames[0].Start != 0 || frames[len(frames)-1].End != int64(len(raw)) {
			t.Fatalf("cut %d: frames = %+v", cut, frames)
		}
	}
}

func TestManagerMidStreamFailsClosed(t *testing.T) {
	for _, partial := range []bool{false, true} {
		t.Run(fmt.Sprint(partial), func(t *testing.T) {
			mgr, st := dpi.NewManager(NewDecoder()), cipState()
			raw := streamFixtures()[1].raw
			if partial {
				raw = raw[5:11]
			}
			pkt := cipSegment(100, raw)
			pkt.FailClosed = true
			for i := 0; i < 2; i++ {
				res := mgr.Inspect(st, pkt)
				var se *dpi.StreamError
				if !res.Framed || !errors.As(res.Err, &se) || se.Kind != dpi.StreamMidStream || se.Proto != "cip" ||
					res.Failed != (i > 0) || len(res.Events) != 0 || len(res.Frames) != 0 {
					t.Fatalf("inspection %d: %+v", i, res)
				}
			}
		})
	}
}

func TestManagerUDPRemainsPacketOnly(t *testing.T) {
	mgr := dpi.NewManager(NewDecoder())
	st := flow.NewState(keyFor("10.0.0.1", "10.0.0.2", 12345, 2222, 17), time.Now())
	raw := streamFixtures()[1].raw
	for _, payload := range [][]byte{raw[:10], raw[10:], append(bytes.Clone(raw), raw...), raw} {
		res := mgr.Inspect(st, &dpi.ParsedPacket{Proto: "udp", Payload: payload, FailClosed: true})
		want, err := NewDecoder().OnPacket(st, &dpi.ParsedPacket{Payload: payload})
		if res.Err != nil || err != nil || res.Framed || res.Proto != "" || len(res.Frames) != 0 {
			t.Fatalf("UDP result = %+v, packet err = %v", res, err)
		}
		assertSameEvents(t, res.Events, want)
	}
}
