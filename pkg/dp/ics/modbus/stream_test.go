// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

package modbus

import (
	"encoding/binary"
	"encoding/hex"
	"errors"
	"github.com/tonylturner/containd/pkg/dp/dpi"
	"github.com/tonylturner/containd/pkg/dp/flow"
	"github.com/tonylturner/containd/pkg/dp/ics/eventfields"
	"github.com/tonylturner/containd/pkg/dp/ics/eventfields/decodertest"
	"reflect"
	"testing"
	"time"
)

var (
	readADU  = []byte{0x00, 0x01, 0x00, 0x00, 0x00, 0x06, 0x01, 0x03, 0x00, 0x00, 0x00, 0x02} // FC 3, 12 bytes
	writeADU = []byte{0x00, 0x02, 0x00, 0x00, 0x00, 0x06, 0x01, 0x06, 0x00, 0x01, 0x00, 0x2A} // FC 6, 12 bytes
)

type span struct{ start, end int64 }

func spans(frames []dpi.DecodedFrame) []span {
	out := []span{}
	for _, f := range frames {
		out = append(out, span{f.Start, f.End})
	}
	return out
}

func concat(parts ...[]byte) []byte {
	var out []byte
	for _, p := range parts {
		out = append(out, p...)
	}
	return out
}

func modbusState() *flow.State {
	return flow.NewState(keyFor("10.0.0.1", "10.0.0.2", 12345, 502), time.Now())
}

func seg(seq uint32, payload []byte) *dpi.ParsedPacket {
	return &dpi.ParsedPacket{Proto: "tcp", SrcPort: 12345, DstPort: 502, Payload: payload, TCPSeq: seq, TCPSeqValid: true}
}

func TestParseStreamFramesEveryADU(t *testing.T) {
	stream := concat(readADU, writeADU, writeADU[:5])
	res, err := NewDecoder().ParseStream(modbusState(), dpi.StreamView{Session: "s", Base: 1000, Bytes: stream})
	if err != nil {
		t.Fatalf("ParseStream: %v", err)
	}
	if got := spans(res.Frames); !reflect.DeepEqual(got, []span{{1000, 1012}, {1012, 1024}}) {
		t.Fatalf("frames %v", got)
	}
	if res.Consumed != 24 || !res.NeedMore {
		t.Fatalf("Consumed=%d NeedMore=%v", res.Consumed, res.NeedMore)
	}
	fc0, _ := eventfields.Uint8(res.Frames[0].Events[0].Attributes, eventfields.KeyFunctionCode)
	fc1, _ := eventfields.Uint8(res.Frames[1].Events[0].Attributes, eventfields.KeyFunctionCode)
	if fc0 != 3 || fc1 != 6 {
		t.Fatalf("function codes %d, %d", fc0, fc1)
	}
	if got := res.Frames[1].Events[0].Attributes["raw_hex"]; got != "00020000000601060001002a" {
		t.Fatalf("raw_hex %v is not the ADU's own bytes", got)
	}
}

func TestParseStreamSplitAtEveryByte(t *testing.T) {
	stream := concat(readADU, writeADU, []byte{0x00, 0x03, 0x00, 0x00, 0x00, 0x00, 0x01})
	decodertest.CheckSplits(t, NewDecoder(), modbusState(), dpi.StreamView{Session: "s", Base: 40, Bytes: stream})
}

func TestParseStreamFrameError(t *testing.T) {
	bad := []byte{0x00, 0x03, 0x00, 0x00, 0x01, 0x00, 0x01, 0x03} // MBAP length 256
	for _, tc := range []struct {
		name   string
		stream []byte
	}{
		{"length above 254", concat(readADU, bad)},
		{"length below 2", concat(readADU, []byte{0x00, 0x03, 0x00, 0x00, 0x00, 0x01, 0x01})},
	} {
		res, err := NewDecoder().ParseStream(modbusState(), dpi.StreamView{Base: 10, Bytes: tc.stream})
		var fe *dpi.FrameError
		if !errors.As(err, &fe) || fe.Offset != 22 {
			t.Fatalf("%s: err = %v, want *FrameError at 22", tc.name, err)
		}
		if got := spans(res.Frames); !reflect.DeepEqual(got, []span{{10, 22}}) || res.Consumed != 12 {
			t.Fatalf("%s: frames %v consumed %d", tc.name, got, res.Consumed)
		}
		if fe.Event.Kind != eventfields.KindMalformed || fe.Event.Proto != eventfields.ProtoModbus {
			t.Fatalf("%s: event %+v", tc.name, fe.Event)
		}
		if msg, ok := eventfields.String(fe.Event.Attributes, eventfields.KeyError); !ok || msg == "" {
			t.Fatalf("%s: malformed event without error", tc.name)
		}
	}
}

// Every cut point of two coalesced ADUs, through the DPI manager that trims
// the consumed prefix: each ADU is decoded exactly once, at the packet that
// completes it.
func TestManagerSplitAtEveryByte(t *testing.T) {
	stream := concat(readADU, writeADU)
	for cut := 1; cut < len(stream); cut++ {
		mgr := dpi.NewManager(NewDecoder())
		st := modbusState()
		first := mgr.Inspect(st, seg(5000, stream[:cut]))
		second := mgr.Inspect(st, seg(5000+uint32(cut), stream[cut:]))
		if first.Err != nil || second.Err != nil || !first.Framed {
			t.Fatalf("cut %d: errors %v / %v framed=%v", cut, first.Err, second.Err, first.Framed)
		}
		for _, f := range first.Frames {
			if f.End > int64(cut) {
				t.Fatalf("cut %d: frame %v decoded before it was complete", cut, f)
			}
		}
		all := append(spans(first.Frames), spans(second.Frames)...)
		if !reflect.DeepEqual(all, []span{{0, 12}, {12, 24}}) {
			t.Fatalf("cut %d: frames %v", cut, all)
		}
		if n := len(first.Events) + len(second.Events); n != 2 {
			t.Fatalf("cut %d: %d events", cut, n)
		}
	}
}

// A read followed by a write on one connection: the write is inspected and
// a retransmission of the read emits nothing.
func TestManagerPersistentConnection(t *testing.T) {
	mgr := dpi.NewManager(NewDecoder())
	st := modbusState()
	steps := []struct {
		pkt  *dpi.ParsedPacket
		want []uint8
	}{
		{seg(100, readADU), []uint8{3}},
		{seg(100, readADU), nil},
		{seg(112, writeADU), []uint8{6}},
	}
	for i, step := range steps {
		res := mgr.Inspect(st, step.pkt)
		var got []uint8
		for _, ev := range res.Events {
			fc, _ := eventfields.Uint8(ev.Attributes, eventfields.KeyFunctionCode)
			got = append(got, fc)
		}
		if res.Err != nil || !reflect.DeepEqual(got, step.want) {
			t.Fatalf("step %d: function codes %v err %v, want %v", i, got, res.Err, step.want)
		}
	}
}

func TestOnPacketUsesStreamParser(t *testing.T) {
	st := modbusState()
	events, err := NewDecoder().OnPacket(st, &dpi.ParsedPacket{Payload: concat(readADU, writeADU)})
	if err != nil || len(events) != 2 {
		t.Fatalf("coalesced: %d events, %v", len(events), err)
	}
	events, err = NewDecoder().OnPacket(st, &dpi.ParsedPacket{Payload: concat(readADU, []byte{0, 0, 0, 0, 0xFF, 0xFF})})
	var fe *dpi.FrameError
	if !errors.As(err, &fe) || len(events) != 2 || events[1].Kind != eventfields.KindMalformed {
		t.Fatalf("unframeable: %d events, %v", len(events), err)
	}
	if events, err := NewDecoder().OnPacket(st, &dpi.ParsedPacket{Payload: readADU[:7]}); err != nil || len(events) != 0 {
		t.Fatalf("partial ADU: %d events, %v", len(events), err)
	}
}

func TestProtocol(t *testing.T) {
	var sd dpi.StreamDecoder = NewDecoder()
	if sd.Protocol() != "modbus" {
		t.Fatalf("Protocol() = %q", sd.Protocol())
	}
}

func adu(tid uint16, fc byte, a, b uint16) []byte {
	out := make([]byte, 12)
	binary.BigEndian.PutUint16(out[0:], tid)
	binary.BigEndian.PutUint16(out[4:], 6)
	out[6] = 1
	out[7] = fc
	binary.BigEndian.PutUint16(out[8:], a)
	binary.BigEndian.PutUint16(out[10:], b)
	return out
}

func mainSeg(seq uint32, payload []byte) *dpi.ParsedPacket {
	return &dpi.ParsedPacket{Proto: "tcp", SrcPort: 40000, DstPort: 502, Payload: payload, TCPSeq: seq, TCPSeqValid: true}
}

func newStreamFixture() (*dpi.Manager, *flow.State) {
	return dpi.NewManager(NewDecoder()), flow.NewState(keyFor("10.0.0.1", "10.0.0.2", 40000, 502), time.Now())
}

func feed(t *testing.T, mgr *dpi.Manager, st *flow.State, pkts ...*dpi.ParsedPacket) []dpi.Event {
	t.Helper()
	var out []dpi.Event
	for _, p := range pkts {
		evs, err := mgr.OnPacket(st, p)
		if err != nil {
			t.Fatalf("OnPacket: %v", err)
		}
		out = append(out, evs...)
	}
	return out
}

func assertFrames(t *testing.T, evs []dpi.Event, want ...[]byte) {
	t.Helper()
	if len(evs) != len(want) {
		t.Fatalf("got %d events, want %d: %+v", len(evs), len(want), evs)
	}
	for i, w := range want {
		if got := evs[i].Attributes["raw_hex"]; got != hex.EncodeToString(w) {
			t.Fatalf("event %d raw_hex = %v, want %x", i, got, w)
		}
	}
}

func TestStreamPersistentReadWriteRead(t *testing.T) {
	mgr, st := newStreamFixture()
	read1, write, read2 := adu(10, 3, 0, 2), adu(11, 6, 1, 0x1234), adu(12, 3, 0, 2)

	evs := feed(t, mgr, st, mainSeg(1000, read1), mainSeg(1012, write), mainSeg(1024, read2))
	assertFrames(t, evs, read1, write, read2)
	want := []struct {
		tid     uint16
		fc      uint8
		isWrite bool
	}{{10, 3, false}, {11, 6, true}, {12, 3, false}}
	for i, w := range want {
		a := evs[i].Attributes
		if a["transaction_id"] != w.tid || a["function_code"] != w.fc || a["is_write"] != w.isWrite {
			t.Fatalf("event %d = %+v, want tid=%d fc=%d is_write=%v", i, a, w.tid, w.fc, w.isWrite)
		}
	}
}

func TestStreamSplitAndCoalescedFrames(t *testing.T) {
	mgr, st := newStreamFixture()
	f1, f2, f3 := adu(1, 3, 0, 2), adu(2, 6, 1, 7), adu(3, 3, 4, 1)
	wire := append(append(append([]byte(nil), f1...), f2...), f3...)

	// f1 split inside the MBAP header, f1 tail + f2 + head of f3
	// coalesced, then the f3 tail.
	evs := feed(t, mgr, st, mainSeg(0, wire[:4]))
	assertFrames(t, evs)
	evs = feed(t, mgr, st, mainSeg(4, wire[4:30]))
	assertFrames(t, evs, f1, f2)
	evs = feed(t, mgr, st, mainSeg(30, wire[30:]))
	assertFrames(t, evs, f3)
}

func TestStreamRetransmissionIsNotReported(t *testing.T) {
	mgr, st := newStreamFixture()
	f1, f2 := adu(1, 3, 0, 2), adu(2, 6, 1, 7)

	evs := feed(t, mgr, st, mainSeg(500, f1), mainSeg(500, f1), mainSeg(512, f2), mainSeg(512, f2), mainSeg(500, f1))
	assertFrames(t, evs, f1, f2)
}

func TestStreamSequenceZeroAndWrap(t *testing.T) {
	mgr, st := newStreamFixture()
	f1, f2 := adu(1, 3, 0, 2), adu(2, 6, 1, 7)
	evs := feed(t, mgr, st, mainSeg(0, f1), mainSeg(0, f1), mainSeg(12, f2))
	assertFrames(t, evs, f1, f2)

	mgr, st = newStreamFixture()
	// f1 occupies 0xFFFFFFFA..0x00000005; f2 starts at 6 after the wrap.
	evs = feed(t, mgr, st, mainSeg(0xFFFFFFFA, f1), mainSeg(6, f2), mainSeg(0xFFFFFFFA, f1))
	assertFrames(t, evs, f1, f2)
}

func TestStreamOverlappingOutOfOrderWrite(t *testing.T) {
	mgr, st := newStreamFixture()
	read, write := adu(1, 3, 0, 2), adu(2, 6, 1, 0x1234)
	wire := append(append([]byte(nil), read...), write...)

	// The write (bytes 12..24) arrives as 16..24 ahead of 4..20, which
	// overlaps it; only the queued segment carries the write's last bytes.
	evs := feed(t, mgr, st, mainSeg(100, wire[:4]), mainSeg(116, wire[16:]))
	assertFrames(t, evs)
	evs = feed(t, mgr, st, mainSeg(104, wire[4:20]))
	assertFrames(t, evs, read, write)
	if a := evs[1].Attributes; a["is_write"] != true || a["function_code"] != uint8(6) {
		t.Fatalf("write event = %+v, want is_write=true function_code=6", a)
	}
}

func TestStreamInvalidHeaderDiscardsBuffer(t *testing.T) {
	mgr, st := newStreamFixture()
	bad := []byte{0, 1, 0, 0, 0, 1, 1, 3} // length 1: no function code
	good := adu(2, 6, 1, 7)
	badResult := mgr.Inspect(st, mainSeg(0, bad))
	if _, ok := badResult.Err.(*dpi.FrameError); !ok || len(badResult.Events) != 1 || badResult.Events[0].Kind != "malformed" {
		t.Fatalf("missing framing evidence: %+v", badResult)
	}
	evs := feed(t, mgr, st, mainSeg(uint32(len(bad)), good))
	assertFrames(t, evs, good)
}

func TestStreamOversizedPartialFrameDiscardsBuffer(t *testing.T) {
	mgr, st := newStreamFixture()
	// MBAP claiming 1000 bytes: no conforming ADU is that long, so the
	// stream must not wait for it.
	huge := []byte{0, 1, 0, 0, 0x03, 0xE8, 1, 3, 0, 0}
	good := adu(2, 6, 1, 7)
	badResult := mgr.Inspect(st, mainSeg(0, huge))
	if _, ok := badResult.Err.(*dpi.FrameError); !ok || len(badResult.Events) != 1 || badResult.Events[0].Kind != "malformed" {
		t.Fatalf("missing framing evidence: %+v", badResult)
	}
	evs := feed(t, mgr, st, mainSeg(uint32(len(huge)), good))
	assertFrames(t, evs, good)
}

// TestStreamEventShapeMatchesSingleFrame pins the per-frame event keys,
// Go types and kind to what a single frame produced before stream
// decoding.
func TestStreamEventShapeMatchesSingleFrame(t *testing.T) {
	mgr, st := newStreamFixture()
	write := adu(11, 6, 1, 0x1234)
	evs := feed(t, mgr, st, mainSeg(0, write))
	if len(evs) != 1 {
		t.Fatalf("got %d events", len(evs))
	}
	ev := evs[0]
	if ev.Proto != "modbus" || ev.Kind != "request" || ev.FlowID != st.Key.Hash() {
		t.Fatalf("unexpected event header: %+v", ev)
	}
	want := map[string]any{
		"transaction_id": uint16(11),
		"unit_id":        uint8(1),
		"function_code":  uint8(6),
		"is_write":       true,
		"address":        uint16(1),
		"quantity":       uint16(0x1234),
		"raw_hex":        hex.EncodeToString(write),
	}
	if !reflect.DeepEqual(ev.Attributes, want) {
		t.Fatalf("attributes = %#v, want %#v", ev.Attributes, want)
	}
}
