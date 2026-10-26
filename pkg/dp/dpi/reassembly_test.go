// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

package dpi

import (
	"bytes"
	"testing"
	"time"

	"github.com/tonylturner/containd/pkg/dp/flow"
)

var testNow = time.Unix(1000, 0).UTC()

func feedSeq(r *reassembler, key string, seq uint32, strict bool, data ...byte) feedResult {
	return r.feed(key, position{kind: posSeq, seq: seq}, data, testNow, strict, false)
}

func feedOff(r *reassembler, key string, off int64, strict bool, data ...byte) feedResult {
	return r.feed(key, position{kind: posOffset, off: off}, data, testNow, strict, true)
}

func wantBuf(t *testing.T, got feedResult, base int64, data ...byte) {
	t.Helper()
	if got.err != nil || got.failed != nil {
		t.Fatalf("err=%v failed=%v", got.err, got.failed)
	}
	if got.base != base || !bytes.Equal(got.buf, data) {
		t.Fatalf("buf %x at %d, want %x at %d", got.buf, got.base, data, base)
	}
}

func wantStreamErr(t *testing.T, got feedResult, kind StreamErrKind, off int64) {
	t.Helper()
	if got.err == nil || got.err.Kind != kind || got.err.Offset != off {
		t.Fatalf("err = %+v, want %v at %d", got.err, kind, off)
	}
}

// storedTotal recomputes the bytes held by every stream.
func storedTotal(r *reassembler) int {
	r.mu.Lock()
	defer r.mu.Unlock()
	n := 0
	for _, s := range r.streams {
		n += s.stored()
	}
	return n
}

func TestReassemblerAccumulatesBySequence(t *testing.T) {
	for _, strict := range []bool{false, true} {
		r := newReassembler(0, time.Minute)
		wantBuf(t, feedSeq(r, "f", 100, strict, 1, 2), 0, 1, 2)
		wantBuf(t, feedSeq(r, "f", 102, strict, 3, 4), 0, 1, 2, 3, 4)
		if streams, held := r.stats(); streams != 1 || held != 4 {
			t.Fatalf("stats = %d streams, %d bytes", streams, held)
		}
	}
}

// Sequence number 0 is a real value, and sequence space wraps.
func TestReassemblerSequenceZeroAndWrap(t *testing.T) {
	r := newReassembler(0, time.Minute)
	wantBuf(t, feedSeq(r, "zero", 0, true, 1, 2), 0, 1, 2)
	wantBuf(t, feedSeq(r, "zero", 2, true, 3), 0, 1, 2, 3)

	wantBuf(t, feedSeq(r, "wrap", 0xfffffffe, true, 1, 2, 3), 0, 1, 2, 3)
	wantBuf(t, feedSeq(r, "wrap", 1, true, 4), 0, 1, 2, 3, 4)
	wantBuf(t, feedSeq(r, "wrap", 0xffffffff, true, 2, 3, 4, 5), 0, 1, 2, 3, 4, 5)
}

// Without sequence metadata, bytes are appended in arrival order.
func TestReassemblerAppendMode(t *testing.T) {
	r := newReassembler(0, time.Minute)
	app := position{kind: posAppend}
	r.feed("f", app, []byte{1, 2}, testNow, true, false)
	got := r.feed("f", app, []byte{1, 2}, testNow, true, false)
	wantBuf(t, got, 0, 1, 2, 1, 2)
	r.trim("f", 0, 4)
	wantBuf(t, r.feed("f", app, []byte{9}, testNow, true, false), 4, 9)
}

func TestReassemblerLenientSlidingWindow(t *testing.T) {
	r := newReassembler(4, time.Minute)
	feedSeq(r, "f", 100, false, 1, 2, 3)
	// Streams without a framed decoder keep the sliding window.
	wantBuf(t, feedSeq(r, "f", 103, false, 4, 5, 6), 2, 3, 4, 5, 6)
	if _, held := r.stats(); held != 4 {
		t.Fatalf("bytes buffered = %d, want 4", held)
	}
}

func TestReassemblerStrictOverflowIsAnError(t *testing.T) {
	r := newReassembler(4, time.Minute)
	feedSeq(r, "f", 100, true, 1, 2, 3)
	wantStreamErr(t, feedSeq(r, "f", 103, true, 4, 5), StreamOverflow, 3)
	// An out-of-order segment beyond the window is an overflow too.
	r2 := newReassembler(4, time.Minute)
	feedSeq(r2, "f", 100, true, 1)
	wantStreamErr(t, feedSeq(r2, "f", 104, true, 5), StreamOverflow, 4)
}

func TestReassemblerOutOfOrderFillsGap(t *testing.T) {
	r := newReassembler(0, time.Minute)
	feedSeq(r, "f", 100, true, 1, 2)
	got := feedSeq(r, "f", 105, true, 5, 6)
	wantBuf(t, feedResult{buf: got.buf, base: got.base}, 0, 1, 2)
	if !got.gap {
		t.Fatal("gap not reported")
	}
	got = feedSeq(r, "f", 102, true, 3, 4, 0x77)
	wantBuf(t, got, 0, 1, 2, 3, 4, 0x77, 5, 6)
	if got.gap {
		t.Fatal("gap still reported after fill")
	}
}

// Session streams start at offset 0: a first segment beyond it is a gap.
func TestReassemblerSessionStreamStartsAtZero(t *testing.T) {
	r := newReassembler(0, time.Minute)
	got := feedOff(r, "s", 3, true, 4, 5)
	if !got.gap || len(got.buf) != 0 || got.base != 0 {
		t.Fatalf("first segment at 3: gap=%v buf=%x base=%d", got.gap, got.buf, got.base)
	}
	wantBuf(t, feedOff(r, "s", 0, true, 1, 2, 3), 0, 1, 2, 3, 4, 5)
}

func TestReassemblerRetransmissionsAreNotCounted(t *testing.T) {
	r := newReassembler(0, time.Minute)
	feedSeq(r, "f", 100, true, 1, 2)
	wantBuf(t, feedSeq(r, "f", 100, true, 1, 2), 0, 1, 2)
	if got := r.retransmissions("f"); got != 1 {
		t.Fatalf("retransmissions = %d, want 1", got)
	}
	if _, held := r.stats(); held != 2 || storedTotal(r) != 2 {
		t.Fatalf("bytes buffered = %d (stored %d), want 2", held, storedTotal(r))
	}
}

func TestReassemblerPartialRetransmission(t *testing.T) {
	r := newReassembler(0, time.Minute)
	feedSeq(r, "f", 100, true, 1, 2, 3)
	wantBuf(t, feedSeq(r, "f", 101, true, 2, 3, 4, 5), 0, 1, 2, 3, 4, 5)
}

// Bytes below the consumed watermark are duplicates, whatever their
// content: the caller owns identity of consumed bytes.
func TestReassemblerConsumedBytesAreDuplicates(t *testing.T) {
	r := newReassembler(0, time.Minute)
	feedSeq(r, "f", 100, true, 1, 2, 3)
	r.trim("f", 0, 2)
	wantBuf(t, feedSeq(r, "f", 100, true, 9, 9, 3, 4), 2, 3, 4)
}

func TestReassemblerOverlapConflict(t *testing.T) {
	r := newReassembler(0, time.Minute)
	feedSeq(r, "f", 100, true, 1, 2, 3)
	wantStreamErr(t, feedSeq(r, "f", 101, true, 2, 9, 4), StreamOverlapConflict, 2)

	lenient := newReassembler(0, time.Minute)
	feedSeq(lenient, "f", 100, false, 1, 2, 3)
	wantBuf(t, feedSeq(lenient, "f", 101, false, 2, 9, 4), 0, 1, 2, 3, 4)
}

func TestReassemblerOverlapConflictBeyondHole(t *testing.T) {
	r := newReassembler(0, time.Minute)
	feedSeq(r, "f", 100, true, 1)
	feedSeq(r, "f", 105, true, 5, 6, 7)
	wantStreamErr(t, feedSeq(r, "f", 106, true, 6, 8), StreamOverlapConflict, 7)
	// The in-order segment that reaches a held one is compared too.
	r2 := newReassembler(0, time.Minute)
	feedSeq(r2, "f", 100, true, 1)
	feedSeq(r2, "f", 103, true, 3, 4)
	wantStreamErr(t, feedSeq(r2, "f", 101, true, 1, 2, 9), StreamOverlapConflict, 3)
}

func TestReassemblerOutOfOrderSegmentsMerge(t *testing.T) {
	r := newReassembler(0, time.Minute)
	feedSeq(r, "f", 100, true, 0)
	for i := uint32(0); i < 3*maxOOOSegments; i++ {
		// Touching segments merge into one hole's worth of data.
		if got := feedSeq(r, "f", 110+i, true, byte(i)); got.err != nil {
			t.Fatalf("segment %d: %v", i, got.err)
		}
	}
	r.mu.Lock()
	n := len(r.streams["f"].ooo)
	r.mu.Unlock()
	if n != 1 {
		t.Fatalf("out-of-order segments = %d, want 1 merged", n)
	}
}

func TestReassemblerOutOfOrderLimit(t *testing.T) {
	for _, strict := range []bool{true, false} {
		r := newReassembler(0, time.Minute)
		feedSeq(r, "f", 100, strict, 1)
		for i := uint32(0); i < maxOOOSegments; i++ {
			if got := feedSeq(r, "f", 110+2*i, strict, 1); got.err != nil {
				t.Fatalf("strict=%v segment %d: %v", strict, i, got.err)
			}
		}
		got := feedSeq(r, "f", 200, strict, 1)
		if strict {
			wantStreamErr(t, got, StreamOutOfOrderLimit, 100)
			continue
		}
		if got.err != nil {
			t.Fatalf("lenient: %v", got.err)
		}
		r.mu.Lock()
		n := len(r.streams["f"].ooo)
		r.mu.Unlock()
		if n != maxOOOSegments {
			t.Fatalf("lenient kept %d segments, want %d", n, maxOOOSegments)
		}
	}
}

func TestReassemblerTrimChecksWatermark(t *testing.T) {
	r := newReassembler(0, time.Minute)
	feedSeq(r, "f", 100, true, 1, 2, 3, 4)
	r.trim("f", 0, 3)
	r.trim("f", 0, 1) // stale view: ignored
	wantBuf(t, feedSeq(r, "f", 104, true, 5), 3, 4, 5)
	if _, held := r.stats(); held != 2 {
		t.Fatalf("bytes buffered = %d, want 2", held)
	}
}

func TestReassemblerFailAndComplete(t *testing.T) {
	r := newReassembler(0, time.Minute)
	feedOff(r, "s", 0, true, 1, 2)
	failure := &StreamError{Kind: StreamOverflow}
	r.fail("s", failure)
	if got := feedOff(r, "s", 2, true, 3); got.failed != failure {
		t.Fatalf("feed after fail = %+v, want the failure", got)
	}
	if r.failure("s") != failure {
		t.Fatal("failure not recorded")
	}
	r.complete("s")
	if r.failure("s") != nil {
		t.Fatal("complete must clear the failure")
	}
	if streams, held := r.stats(); streams != 0 || held != 0 {
		t.Fatalf("stats after complete = %d, %d", streams, held)
	}
}

func TestReassemblerSweepKeepsSessionStreams(t *testing.T) {
	r := newReassembler(0, 5*time.Second)
	t0 := testNow
	r.feed("legacy", position{kind: posSeq, seq: 1}, []byte{1}, t0, false, false)
	r.feed("fresh", position{kind: posSeq, seq: 1}, []byte{1}, t0.Add(4*time.Second), false, false)
	r.feed("session", position{kind: posOffset}, []byte{1}, t0, true, true)
	r.sweep(t0.Add(6 * time.Second))
	r.mu.Lock()
	_, legacy := r.streams["legacy"]
	_, fresh := r.streams["fresh"]
	_, session := r.streams["session"]
	r.mu.Unlock()
	if legacy || !fresh || !session {
		t.Fatalf("after sweep legacy=%v fresh=%v session=%v", legacy, fresh, session)
	}
	if streams, held := r.stats(); streams != 2 || held != 2 {
		t.Fatalf("stats = %d, %d", streams, held)
	}
}

// mockStreamDecoder is a framed decoder for a simple framing: the first
// byte is the frame's payload length, followed by that many bytes. A length
// byte of 0xFF cannot be framed.
type mockStreamDecoder struct {
	onPacketCalls int
	scribble      bool // overwrite v.Bytes after parsing (misbehaving decoder)
}

func (m *mockStreamDecoder) Supports(_ *flow.State) bool { return true }

func (m *mockStreamDecoder) OnPacket(_ *flow.State, _ *ParsedPacket) ([]Event, error) {
	m.onPacketCalls++
	return nil, nil
}

func (m *mockStreamDecoder) OnFlowEnd(_ *flow.State) ([]Event, error) { return nil, nil }

func (m *mockStreamDecoder) Protocol() string { return "mock" }

func (m *mockStreamDecoder) ParseStream(_ *flow.State, v StreamView) (StreamResult, error) {
	var res StreamResult
	defer func() {
		if m.scribble {
			for i := range v.Bytes {
				v.Bytes[i] = 0xEE
			}
		}
	}()
	off := 0
	for off < len(v.Bytes) {
		n := int(v.Bytes[off])
		if n == 0xFF {
			at := v.Base + int64(off)
			return res, &FrameError{Offset: at, Reason: "bad length", Event: Event{Proto: "mock", Kind: "malformed", Attributes: map[string]any{"start": at}}}
		}
		if off+1+n > len(v.Bytes) {
			res.NeedMore = true
			break
		}
		start := v.Base + int64(off)
		end := start + int64(1+n)
		res.Frames = append(res.Frames, DecodedFrame{Start: start, End: end, Events: []Event{{Proto: "mock", Kind: "test-frame", Attributes: map[string]any{"start": start}}}})
		off += 1 + n
	}
	res.Consumed = off
	return res, nil
}

func TestIntegrationReassemblyWithStreamDecoder(t *testing.T) {
	dec := &mockStreamDecoder{}
	mgr := NewManager(dec)

	st := flow.NewState(flow.Key{}, time.Now())

	// Send a framed message split across two TCP segments.
	// Frame: length=3, payload=0xAA 0xBB 0xCC -> total 4 bytes.
	// Segment 1: first 2 bytes.
	pkt1 := &ParsedPacket{Proto: "tcp", Payload: []byte{0x03, 0xAA}, TCPSeq: 1000}
	events, err := mgr.OnPacket(st, pkt1)
	if err != nil {
		t.Fatalf("segment 1: %v", err)
	}
	if len(events) != 0 {
		t.Fatalf("segment 1: expected 0 events (incomplete), got %d", len(events))
	}

	// Segment 2: remaining 2 bytes.
	pkt2 := &ParsedPacket{Proto: "tcp", Payload: []byte{0xBB, 0xCC}, TCPSeq: 1002}
	events, err = mgr.OnPacket(st, pkt2)
	if err != nil {
		t.Fatalf("segment 2: %v", err)
	}
	if len(events) != 1 {
		t.Fatalf("segment 2: expected 1 event, got %d", len(events))
	}
	if events[0].Kind != "test-frame" {
		t.Fatalf("unexpected event kind: %s", events[0].Kind)
	}

	// After consuming, the reassembler buffer should be trimmed.
	// Feeding an empty payload should return only residual data (none).
	// We verify by sending the start of a new frame.
	pkt3 := &ParsedPacket{Proto: "tcp", Payload: []byte{0x01, 0xFF}, TCPSeq: 1004}
	events, err = mgr.OnPacket(st, pkt3)
	if err != nil {
		t.Fatalf("segment 3: %v", err)
	}
	if len(events) != 1 {
		t.Fatalf("segment 3: expected 1 event (complete 1-byte frame), got %d", len(events))
	}
	if dec.onPacketCalls != 0 {
		t.Fatalf("framed decoder OnPacket called %d times on TCP", dec.onPacketCalls)
	}
}

func TestIntegrationModbusStyleReassembly(t *testing.T) {
	// Simulate a Modbus-style response split across two TCP segments.
	// Modbus TCP header: TxID(2) + ProtoID(2) + Length(2) + UnitID(1) + FC(1) + Data
	// We use a simple decoder that just checks for a minimum header size.
	dec := &mockStreamDecoder{}
	mgr := NewManager(dec)

	st := flow.NewState(flow.Key{}, time.Now())

	// Frame: length byte = 7, then 7 bytes of "Modbus" payload.
	// Split across two segments.
	frame := []byte{0x07, 0x00, 0x01, 0x00, 0x00, 0x00, 0x03, 0x01}
	seg1 := &ParsedPacket{Proto: "tcp", Payload: frame[:3], TCPSeq: 500}
	seg2 := &ParsedPacket{Proto: "tcp", Payload: frame[3:], TCPSeq: 503}

	events1, _ := mgr.OnPacket(st, seg1)
	if len(events1) != 0 {
		t.Fatalf("modbus seg1: expected 0 events, got %d", len(events1))
	}

	events2, _ := mgr.OnPacket(st, seg2)
	if len(events2) != 1 {
		t.Fatalf("modbus seg2: expected 1 event, got %d", len(events2))
	}
	if dec.onPacketCalls != 0 {
		t.Fatalf("framed decoder OnPacket called %d times on TCP", dec.onPacketCalls)
	}
}

func TestNonTCPBypassesReassembly(t *testing.T) {
	dec := &mockDecoder{support: true}
	mgr := NewManager(dec)

	st := flow.NewState(flow.Key{}, time.Now())
	pkt := &ParsedPacket{Proto: "udp", Payload: []byte{0x01}}

	_, err := mgr.OnPacket(st, pkt)
	if err != nil {
		t.Fatalf("udp: %v", err)
	}
	if dec.calls != 1 {
		t.Fatalf("udp: expected 1 call, got %d", dec.calls)
	}
	// Reassembler should have no streams.
	if streams, _ := mgr.reassembler.stats(); streams != 0 {
		t.Fatalf("reassembler should have 0 streams for UDP, got %d", streams)
	}
}
