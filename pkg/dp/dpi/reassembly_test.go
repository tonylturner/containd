// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

package dpi

import (
	"bytes"
	"testing"
	"time"

	"github.com/tonylturner/containd/pkg/dp/flow"
)

func TestFeedAccumulatesData(t *testing.T) {
	r := NewReassembler(0, time.Minute)
	now := time.Now()

	buf1 := r.Feed("flow1", []byte{0x01, 0x02}, now, 100)
	if !bytes.Equal(buf1, []byte{0x01, 0x02}) {
		t.Fatalf("first feed: got %x, want 0102", buf1)
	}

	buf2 := r.Feed("flow1", []byte{0x03, 0x04}, now, 102)
	if !bytes.Equal(buf2, []byte{0x01, 0x02, 0x03, 0x04}) {
		t.Fatalf("second feed: got %x, want 01020304", buf2)
	}

	if r.ActiveStreams != 1 {
		t.Fatalf("active streams: got %d, want 1", r.ActiveStreams)
	}
	if r.BytesBuffered != 4 {
		t.Fatalf("bytes buffered: got %d, want 4", r.BytesBuffered)
	}
}

func TestFeedSlidingWindow(t *testing.T) {
	// maxSize = 4 bytes
	r := NewReassembler(4, time.Minute)
	now := time.Now()

	r.Feed("flow1", []byte{0x01, 0x02, 0x03}, now, 100)
	buf := r.Feed("flow1", []byte{0x04, 0x05, 0x06}, now, 103)

	// 6 bytes total, max 4 -> oldest 2 bytes discarded
	want := []byte{0x03, 0x04, 0x05, 0x06}
	if !bytes.Equal(buf, want) {
		t.Fatalf("sliding window: got %x, want %x", buf, want)
	}
}

func TestCompleteRemovesStream(t *testing.T) {
	r := NewReassembler(0, time.Minute)
	now := time.Now()

	r.Feed("flow1", []byte{0x01}, now, 100)
	r.Feed("flow2", []byte{0x02}, now, 200)

	if r.ActiveStreams != 2 {
		t.Fatalf("before complete: active=%d, want 2", r.ActiveStreams)
	}

	r.Complete("flow1")
	if r.ActiveStreams != 1 {
		t.Fatalf("after complete: active=%d, want 1", r.ActiveStreams)
	}

	// Feed to flow1 again should start fresh.
	buf := r.Feed("flow1", []byte{0xAA}, now, 300)
	if !bytes.Equal(buf, []byte{0xAA}) {
		t.Fatalf("after complete+feed: got %x, want aa", buf)
	}
}

func TestSweepRemovesIdleStreams(t *testing.T) {
	r := NewReassembler(0, 5*time.Second)
	t0 := time.Now()

	r.Feed("flow1", []byte{0x01}, t0, 100)
	r.Feed("flow2", []byte{0x02}, t0.Add(4*time.Second), 200)

	// At t0+6s, flow1 is 6s idle (>5s), flow2 is 2s idle (<5s).
	r.Sweep(t0.Add(6 * time.Second))

	if r.ActiveStreams != 1 {
		t.Fatalf("after sweep: active=%d, want 1", r.ActiveStreams)
	}

	// Verify flow2 still works.
	buf := r.Feed("flow2", []byte{0x03}, t0.Add(6*time.Second), 201)
	if !bytes.Equal(buf, []byte{0x02, 0x03}) {
		t.Fatalf("flow2 after sweep: got %x, want 0203", buf)
	}
}

func TestTrimConsumedBytes(t *testing.T) {
	r := NewReassembler(0, time.Minute)
	now := time.Now()

	r.Feed("flow1", []byte{0x01, 0x02, 0x03, 0x04, 0x05}, now, 100)
	r.Trim("flow1", 3)

	buf := r.Feed("flow1", []byte{0x06}, now, 105)
	want := []byte{0x04, 0x05, 0x06}
	if !bytes.Equal(buf, want) {
		t.Fatalf("after trim+feed: got %x, want %x", buf, want)
	}
}

func TestFeedOutOfOrder(t *testing.T) {
	r := NewReassembler(0, time.Minute)
	now := time.Now()

	// Send segment 1 (seq=100, 2 bytes).
	r.Feed("flow1", []byte{0x01, 0x02}, now, 100)

	// Send segment 3 (seq=105, 2 bytes) — skipping segment 2.
	buf := r.Feed("flow1", []byte{0x05, 0x06}, now, 105)
	// Should only have segment 1 data; segment 3 is buffered OOO.
	if !bytes.Equal(buf, []byte{0x01, 0x02}) {
		t.Fatalf("after OOO: got %x, want 0102", buf)
	}

	// Send segment 2 (seq=102, 3 bytes) — fills the gap.
	buf = r.Feed("flow1", []byte{0x03, 0x04, 0x77}, now, 102)
	// Now all three segments should be flushed in order.
	want := []byte{0x01, 0x02, 0x03, 0x04, 0x77, 0x05, 0x06}
	if !bytes.Equal(buf, want) {
		t.Fatalf("after gap fill: got %x, want %x", buf, want)
	}
}

func TestFeedRetransmission(t *testing.T) {
	r := NewReassembler(0, time.Minute)
	now := time.Now()

	// Send segment 1.
	r.Feed("flow1", []byte{0x01, 0x02}, now, 100)
	// Retransmit segment 1.
	buf := r.Feed("flow1", []byte{0x01, 0x02}, now, 100)
	// Should still have only 2 bytes.
	if !bytes.Equal(buf, []byte{0x01, 0x02}) {
		t.Fatalf("after retransmit: got %x, want 0102", buf)
	}

	retrans := r.Retransmissions("flow1")
	if retrans != 1 {
		t.Fatalf("retransmissions: got %d, want 1", retrans)
	}
}

func TestFeedOOOBufferBounded(t *testing.T) {
	r := NewReassembler(0, time.Minute)
	now := time.Now()

	// First in-order segment.
	r.Feed("flow1", []byte{0x01}, now, 100)

	// Send 5 OOO segments (only 4 should be buffered).
	for i := uint32(0); i < 5; i++ {
		r.Feed("flow1", []byte{byte(0x10 + i)}, now, 200+i*10)
	}

	r.mu.Lock()
	oooLen := len(r.streams["flow1"].ooo)
	r.mu.Unlock()
	if oooLen != 4 {
		t.Fatalf("OOO buffer: got %d segments, want 4 (bounded)", oooLen)
	}
}

func TestFeedPartialRetransmission(t *testing.T) {
	r := NewReassembler(0, time.Minute)
	now := time.Now()

	// Send 3 bytes at seq 100.
	r.Feed("flow1", []byte{0x01, 0x02, 0x03}, now, 100)

	// Send overlapping segment: seq 101, 4 bytes — 2 bytes overlap, 2 new.
	buf := r.Feed("flow1", []byte{0x02, 0x03, 0x04, 0x05}, now, 101)
	want := []byte{0x01, 0x02, 0x03, 0x04, 0x05}
	if !bytes.Equal(buf, want) {
		t.Fatalf("partial retransmit: got %x, want %x", buf, want)
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
	if mgr.reassembler.ActiveStreams != 0 {
		t.Fatalf("reassembler should have 0 streams for UDP, got %d", mgr.reassembler.ActiveStreams)
	}
}
