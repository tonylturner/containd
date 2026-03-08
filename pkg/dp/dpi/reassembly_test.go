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

	buf1 := r.Feed("flow1", []byte{0x01, 0x02}, now)
	if !bytes.Equal(buf1, []byte{0x01, 0x02}) {
		t.Fatalf("first feed: got %x, want 0102", buf1)
	}

	buf2 := r.Feed("flow1", []byte{0x03, 0x04}, now)
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

	r.Feed("flow1", []byte{0x01, 0x02, 0x03}, now)
	buf := r.Feed("flow1", []byte{0x04, 0x05, 0x06}, now)

	// 6 bytes total, max 4 → oldest 2 bytes discarded
	want := []byte{0x03, 0x04, 0x05, 0x06}
	if !bytes.Equal(buf, want) {
		t.Fatalf("sliding window: got %x, want %x", buf, want)
	}
}

func TestCompleteRemovesStream(t *testing.T) {
	r := NewReassembler(0, time.Minute)
	now := time.Now()

	r.Feed("flow1", []byte{0x01}, now)
	r.Feed("flow2", []byte{0x02}, now)

	if r.ActiveStreams != 2 {
		t.Fatalf("before complete: active=%d, want 2", r.ActiveStreams)
	}

	r.Complete("flow1")
	if r.ActiveStreams != 1 {
		t.Fatalf("after complete: active=%d, want 1", r.ActiveStreams)
	}

	// Feed to flow1 again should start fresh.
	buf := r.Feed("flow1", []byte{0xAA}, now)
	if !bytes.Equal(buf, []byte{0xAA}) {
		t.Fatalf("after complete+feed: got %x, want aa", buf)
	}
}

func TestSweepRemovesIdleStreams(t *testing.T) {
	r := NewReassembler(0, 5*time.Second)
	t0 := time.Now()

	r.Feed("flow1", []byte{0x01}, t0)
	r.Feed("flow2", []byte{0x02}, t0.Add(4*time.Second))

	// At t0+6s, flow1 is 6s idle (>5s), flow2 is 2s idle (<5s).
	r.Sweep(t0.Add(6 * time.Second))

	if r.ActiveStreams != 1 {
		t.Fatalf("after sweep: active=%d, want 1", r.ActiveStreams)
	}

	// Verify flow2 still works.
	buf := r.Feed("flow2", []byte{0x03}, t0.Add(6*time.Second))
	if !bytes.Equal(buf, []byte{0x02, 0x03}) {
		t.Fatalf("flow2 after sweep: got %x, want 0203", buf)
	}
}

func TestTrimConsumedBytes(t *testing.T) {
	r := NewReassembler(0, time.Minute)
	now := time.Now()

	r.Feed("flow1", []byte{0x01, 0x02, 0x03, 0x04, 0x05}, now)
	r.Trim("flow1", 3)

	buf := r.Feed("flow1", []byte{0x06}, now)
	want := []byte{0x04, 0x05, 0x06}
	if !bytes.Equal(buf, want) {
		t.Fatalf("after trim+feed: got %x, want %x", buf, want)
	}
}

// mockStreamDecoder implements both Decoder and StreamDecoder. It parses
// a simple framing: first byte is the message length, followed by that
// many bytes of payload.  It reports ConsumedBytes accordingly.
type mockStreamDecoder struct {
	consumed int
	events   int
}

func (m *mockStreamDecoder) Supports(_ *flow.State) bool { return true }

func (m *mockStreamDecoder) OnPacket(_ *flow.State, pkt *ParsedPacket) ([]Event, error) {
	m.consumed = 0
	buf := pkt.Payload
	if len(buf) == 0 {
		return nil, nil
	}
	msgLen := int(buf[0])
	if len(buf) < 1+msgLen {
		// Incomplete message; wait for more data.
		return nil, nil
	}
	// Complete message found.
	m.consumed = 1 + msgLen
	m.events++
	return []Event{{Kind: "test-frame", Proto: "tcp"}}, nil
}

func (m *mockStreamDecoder) OnFlowEnd(_ *flow.State) ([]Event, error) { return nil, nil }

func (m *mockStreamDecoder) ConsumedBytes() int { return m.consumed }

func TestIntegrationReassemblyWithStreamDecoder(t *testing.T) {
	dec := &mockStreamDecoder{}
	mgr := NewManager(dec)

	st := flow.NewState(flow.Key{}, time.Now())

	// Send a framed message split across two TCP segments.
	// Frame: length=3, payload=0xAA 0xBB 0xCC → total 4 bytes.
	// Segment 1: first 2 bytes.
	pkt1 := &ParsedPacket{Proto: "tcp", Payload: []byte{0x03, 0xAA}}
	events, err := mgr.OnPacket(st, pkt1)
	if err != nil {
		t.Fatalf("segment 1: %v", err)
	}
	if len(events) != 0 {
		t.Fatalf("segment 1: expected 0 events (incomplete), got %d", len(events))
	}

	// Segment 2: remaining 2 bytes.
	pkt2 := &ParsedPacket{Proto: "tcp", Payload: []byte{0xBB, 0xCC}}
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
	pkt3 := &ParsedPacket{Proto: "tcp", Payload: []byte{0x01, 0xFF}}
	events, err = mgr.OnPacket(st, pkt3)
	if err != nil {
		t.Fatalf("segment 3: %v", err)
	}
	if len(events) != 1 {
		t.Fatalf("segment 3: expected 1 event (complete 1-byte frame), got %d", len(events))
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
	seg1 := &ParsedPacket{Proto: "tcp", Payload: frame[:3]}
	seg2 := &ParsedPacket{Proto: "tcp", Payload: frame[3:]}

	events1, _ := mgr.OnPacket(st, seg1)
	if len(events1) != 0 {
		t.Fatalf("modbus seg1: expected 0 events, got %d", len(events1))
	}

	events2, _ := mgr.OnPacket(st, seg2)
	if len(events2) != 1 {
		t.Fatalf("modbus seg2: expected 1 event, got %d", len(events2))
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
