// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

package modbus

import (
	"encoding/binary"
	"encoding/hex"
	"reflect"
	"testing"
	"time"

	"github.com/tonylturner/containd/pkg/dp/dpi"
	"github.com/tonylturner/containd/pkg/dp/flow"
)

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

func seg(seq uint32, payload []byte) *dpi.ParsedPacket {
	return &dpi.ParsedPacket{Proto: "tcp", SrcPort: 40000, DstPort: 502, Payload: payload, TCPSeq: seq, HasTCPSeq: true}
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

	evs := feed(t, mgr, st, seg(1000, read1), seg(1012, write), seg(1024, read2))
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
	evs := feed(t, mgr, st, seg(0, wire[:4]))
	assertFrames(t, evs)
	evs = feed(t, mgr, st, seg(4, wire[4:30]))
	assertFrames(t, evs, f1, f2)
	evs = feed(t, mgr, st, seg(30, wire[30:]))
	assertFrames(t, evs, f3)
}

func TestStreamRetransmissionIsNotReported(t *testing.T) {
	mgr, st := newStreamFixture()
	f1, f2 := adu(1, 3, 0, 2), adu(2, 6, 1, 7)

	evs := feed(t, mgr, st, seg(500, f1), seg(500, f1), seg(512, f2), seg(512, f2), seg(500, f1))
	assertFrames(t, evs, f1, f2)
}

func TestStreamSequenceZeroAndWrap(t *testing.T) {
	mgr, st := newStreamFixture()
	f1, f2 := adu(1, 3, 0, 2), adu(2, 6, 1, 7)
	evs := feed(t, mgr, st, seg(0, f1), seg(0, f1), seg(12, f2))
	assertFrames(t, evs, f1, f2)

	mgr, st = newStreamFixture()
	// f1 occupies 0xFFFFFFFA..0x00000005; f2 starts at 6 after the wrap.
	evs = feed(t, mgr, st, seg(0xFFFFFFFA, f1), seg(6, f2), seg(0xFFFFFFFA, f1))
	assertFrames(t, evs, f1, f2)
}

func TestStreamInvalidHeaderDiscardsBuffer(t *testing.T) {
	mgr, st := newStreamFixture()
	bad := []byte{0, 1, 0, 0, 0, 1, 1, 3} // length 1: no function code
	good := adu(2, 6, 1, 7)
	evs := feed(t, mgr, st, seg(0, bad), seg(8, good))
	assertFrames(t, evs, good)
}

func TestStreamOversizedPartialFrameDiscardsBuffer(t *testing.T) {
	mgr, st := newStreamFixture()
	// MBAP claiming 1000 bytes: no conforming ADU is that long, so the
	// stream must not wait for it.
	huge := []byte{0, 1, 0, 0, 0x03, 0xE8, 1, 3, 0, 0}
	good := adu(2, 6, 1, 7)
	evs := feed(t, mgr, st, seg(0, huge), seg(10, good))
	assertFrames(t, evs, good)
}

// TestStreamEventShapeMatchesSingleFrame pins the per-frame event keys,
// Go types and kind to what a single frame produced before stream
// decoding.
func TestStreamEventShapeMatchesSingleFrame(t *testing.T) {
	mgr, st := newStreamFixture()
	write := adu(11, 6, 1, 0x1234)
	evs := feed(t, mgr, st, seg(0, write))
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
