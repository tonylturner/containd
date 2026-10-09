// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

package dpi

import (
	"bytes"
	"math/rand/v2"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/tonylturner/containd/pkg/dp/flow"
)

func TestFeedAccumulatesData(t *testing.T) {
	r := NewReassembler(0, time.Minute)
	now := time.Now()

	buf1 := r.Feed("flow1", []byte{0x01, 0x02}, now, 100, true)
	if !bytes.Equal(buf1, []byte{0x01, 0x02}) {
		t.Fatalf("first feed: got %x, want 0102", buf1)
	}

	buf2 := r.Feed("flow1", []byte{0x03, 0x04}, now, 102, true)
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

	r.Feed("flow1", []byte{0x01, 0x02, 0x03}, now, 100, true)
	buf := r.Feed("flow1", []byte{0x04, 0x05, 0x06}, now, 103, true)

	// 6 bytes total, max 4 -> oldest 2 bytes discarded
	want := []byte{0x03, 0x04, 0x05, 0x06}
	if !bytes.Equal(buf, want) {
		t.Fatalf("sliding window: got %x, want %x", buf, want)
	}
}

func TestCompleteRemovesStream(t *testing.T) {
	r := NewReassembler(0, time.Minute)
	now := time.Now()

	r.Feed("flow1", []byte{0x01}, now, 100, true)
	r.Feed("flow2", []byte{0x02}, now, 200, true)

	if r.ActiveStreams != 2 {
		t.Fatalf("before complete: active=%d, want 2", r.ActiveStreams)
	}

	r.Complete("flow1")
	if r.ActiveStreams != 1 {
		t.Fatalf("after complete: active=%d, want 1", r.ActiveStreams)
	}

	// Feed to flow1 again should start fresh.
	buf := r.Feed("flow1", []byte{0xAA}, now, 300, true)
	if !bytes.Equal(buf, []byte{0xAA}) {
		t.Fatalf("after complete+feed: got %x, want aa", buf)
	}
}

func TestSweepRemovesIdleStreams(t *testing.T) {
	r := NewReassembler(0, 5*time.Second)
	t0 := time.Now()

	r.Feed("flow1", []byte{0x01}, t0, 100, true)
	r.Feed("flow2", []byte{0x02}, t0.Add(4*time.Second), 200, true)

	// At t0+6s, flow1 is 6s idle (>5s), flow2 is 2s idle (<5s).
	r.Sweep(t0.Add(6 * time.Second))

	if r.ActiveStreams != 1 {
		t.Fatalf("after sweep: active=%d, want 1", r.ActiveStreams)
	}

	// Verify flow2 still works.
	buf := r.Feed("flow2", []byte{0x03}, t0.Add(6*time.Second), 201, true)
	if !bytes.Equal(buf, []byte{0x02, 0x03}) {
		t.Fatalf("flow2 after sweep: got %x, want 0203", buf)
	}
}

func TestTrimConsumedBytes(t *testing.T) {
	r := NewReassembler(0, time.Minute)
	now := time.Now()

	r.Feed("flow1", []byte{0x01, 0x02, 0x03, 0x04, 0x05}, now, 100, true)
	r.Trim("flow1", 3)

	buf := r.Feed("flow1", []byte{0x06}, now, 105, true)
	want := []byte{0x04, 0x05, 0x06}
	if !bytes.Equal(buf, want) {
		t.Fatalf("after trim+feed: got %x, want %x", buf, want)
	}
}

func TestFeedOutOfOrder(t *testing.T) {
	r := NewReassembler(0, time.Minute)
	now := time.Now()

	// Send segment 1 (seq=100, 2 bytes).
	r.Feed("flow1", []byte{0x01, 0x02}, now, 100, true)

	// Send segment 3 (seq=105, 2 bytes) — skipping segment 2.
	buf := r.Feed("flow1", []byte{0x05, 0x06}, now, 105, true)
	// Should only have segment 1 data; segment 3 is buffered OOO.
	if !bytes.Equal(buf, []byte{0x01, 0x02}) {
		t.Fatalf("after OOO: got %x, want 0102", buf)
	}

	// Send segment 2 (seq=102, 3 bytes) — fills the gap.
	buf = r.Feed("flow1", []byte{0x03, 0x04, 0x77}, now, 102, true)
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
	r.Feed("flow1", []byte{0x01, 0x02}, now, 100, true)
	// Retransmit segment 1.
	buf := r.Feed("flow1", []byte{0x01, 0x02}, now, 100, true)
	// Should still have only 2 bytes.
	if !bytes.Equal(buf, []byte{0x01, 0x02}) {
		t.Fatalf("after retransmit: got %x, want 0102", buf)
	}

	retrans := r.Retransmissions("flow1")
	if retrans != 1 {
		t.Fatalf("retransmissions: got %d, want 1", retrans)
	}
}

func TestFeedSkipsLostGap(t *testing.T) {
	r := NewReassembler(0, time.Minute)
	now := time.Now()

	r.Feed("flow1", []byte{0x01}, now, 100, true)
	// Bytes 101..109 are never seen. Fill the OOO buffer with later
	// segments; they must not be released while the gap may still fill.
	for i := uint32(0); i < maxOOOSegments; i++ {
		buf := r.Feed("flow1", []byte{byte(0x10 + i)}, now, 110+i, true)
		if !bytes.Equal(buf, []byte{0x01}) {
			t.Fatalf("segment %d released across gap: %x", i, buf)
		}
	}
	// One more segment means the gap is lost: the stream resumes at the
	// earliest buffered segment and drops the bytes before the gap.
	buf := r.Feed("flow1", []byte{0x14}, now, 110+maxOOOSegments, true)
	want := []byte{0x10, 0x11, 0x12, 0x13, 0x14}
	if !bytes.Equal(buf, want) {
		t.Fatalf("after gap skip: got %x, want %x", buf, want)
	}
}

func TestFeedSequenceZeroIsTracked(t *testing.T) {
	r := NewReassembler(0, time.Minute)
	now := time.Now()

	r.Feed("flow1", []byte{0x01, 0x02}, now, 0, true)
	// A retransmission at seq 0 must not be appended again.
	if buf := r.Feed("flow1", []byte{0x01, 0x02}, now, 0, true); !bytes.Equal(buf, []byte{0x01, 0x02}) {
		t.Fatalf("seq 0 retransmission appended: %x", buf)
	}
	if buf := r.Feed("flow1", []byte{0x03}, now, 2, true); !bytes.Equal(buf, []byte{0x01, 0x02, 0x03}) {
		t.Fatalf("segment after seq 0: got %x", buf)
	}
}

func TestFeedSequenceWrap(t *testing.T) {
	r := NewReassembler(0, time.Minute)
	now := time.Now()

	r.Feed("flow1", []byte{0x01, 0x02}, now, 0xFFFFFFFE, true)
	buf := r.Feed("flow1", []byte{0x03, 0x04}, now, 0, true)
	if !bytes.Equal(buf, []byte{0x01, 0x02, 0x03, 0x04}) {
		t.Fatalf("across wrap: got %x", buf)
	}
	// Retransmission of the pre-wrap segment.
	buf = r.Feed("flow1", []byte{0x01, 0x02}, now, 0xFFFFFFFE, true)
	if !bytes.Equal(buf, []byte{0x01, 0x02, 0x03, 0x04}) {
		t.Fatalf("pre-wrap retransmission appended: %x", buf)
	}
}

func TestFeedWithoutSequenceAppends(t *testing.T) {
	r := NewReassembler(0, time.Minute)
	now := time.Now()

	r.Feed("flow1", []byte{0x01}, now, 0, false)
	buf := r.Feed("flow1", []byte{0x01}, now, 0, false)
	if !bytes.Equal(buf, []byte{0x01, 0x01}) {
		t.Fatalf("unsequenced segments: got %x, want 0101", buf)
	}
}

func TestFeedPartialRetransmission(t *testing.T) {
	r := NewReassembler(0, time.Minute)
	now := time.Now()

	// Send 3 bytes at seq 100.
	r.Feed("flow1", []byte{0x01, 0x02, 0x03}, now, 100, true)

	// Send overlapping segment: seq 101, 4 bytes — 2 bytes overlap, 2 new.
	buf := r.Feed("flow1", []byte{0x02, 0x03, 0x04, 0x05}, now, 101, true)
	want := []byte{0x01, 0x02, 0x03, 0x04, 0x05}
	if !bytes.Equal(buf, want) {
		t.Fatalf("partial retransmit: got %x, want %x", buf, want)
	}
}

// seqBytes returns n bytes whose values follow their offset, so a lost,
// duplicated or misplaced byte shows up in a comparison.
func seqBytes(n int) []byte {
	out := make([]byte, n)
	for i := range out {
		out[i] = byte(i*7 + i/256)
	}
	return out
}

func TestFeedQueuedSegmentTailPastNextSeq(t *testing.T) {
	r := NewReassembler(0, time.Minute)
	now := time.Now()
	data := seqBytes(40) // seq 100..140

	r.Open("flow1", 100, now)
	r.Feed("flow1", data[20:40], now, 120, true)
	// 100..130 overlaps the queued 120..140; its tail 130..140 must still
	// be appended.
	buf := r.Feed("flow1", data[0:30], now, 100, true)
	if !bytes.Equal(buf, data) {
		t.Fatalf("got %x, want %x", buf, data)
	}
}

func TestFeedOOOSameSeqKeepsLongerCopy(t *testing.T) {
	r := NewReassembler(0, time.Minute)
	now := time.Now()
	data := seqBytes(40)

	r.Open("flow1", 100, now)
	r.Feed("flow1", data[20:25], now, 120, true)
	r.Feed("flow1", data[20:40], now, 120, true)
	// A shorter copy arriving after the longer one adds nothing.
	r.Feed("flow1", data[20:30], now, 120, true)
	buf := r.Feed("flow1", data[0:20], now, 100, true)
	if !bytes.Equal(buf, data) {
		t.Fatalf("got %x, want %x", buf, data)
	}
}

func TestFeedOOOPartialAndContainedOverlaps(t *testing.T) {
	r := NewReassembler(0, time.Minute)
	now := time.Now()
	data := seqBytes(60)

	r.Open("flow1", 100, now)
	r.Feed("flow1", data[20:40], now, 120, true) // queued
	r.Feed("flow1", data[30:50], now, 130, true) // overlaps its tail
	r.Feed("flow1", data[15:25], now, 115, true) // overlaps its head
	r.Feed("flow1", data[32:38], now, 132, true) // contained in a queued one
	r.Feed("flow1", data[50:60], now, 150, true) // adjacent
	buf := r.Feed("flow1", data[0:15], now, 100, true)
	if !bytes.Equal(buf, data) {
		t.Fatalf("got %x, want %x", buf, data)
	}
}

func TestFeedOOOCoveringSegmentReplacesQueued(t *testing.T) {
	r := NewReassembler(0, time.Minute)
	now := time.Now()
	data := seqBytes(40)

	r.Open("flow1", 100, now)
	for i := 0; i < maxOOOSegments; i++ {
		off := 10 + 2*i
		r.Feed("flow1", data[off:off+1], now, uint32(100+off), true)
	}
	// One segment covering every queued one frees their slots, so the
	// next out-of-order segment must not be taken for a lost gap.
	r.Feed("flow1", data[10:20], now, 110, true)
	r.Feed("flow1", data[30:40], now, 130, true)
	r.Feed("flow1", data[20:30], now, 120, true)
	buf := r.Feed("flow1", data[0:10], now, 100, true)
	if !bytes.Equal(buf, data) {
		t.Fatalf("got %x, want %x", buf, data)
	}
}

type testSeg struct{ start, end int }

// overlappingCover returns segments covering [0, n) with overlaps,
// duplicates and segments contained in others.
func overlappingCover(rng *rand.Rand, n int) []testSeg {
	var segs []testSeg
	for pos := 0; pos < n; {
		start := max(0, pos-rng.IntN(16))
		end := min(n, pos+1+rng.IntN(32))
		segs = append(segs, testSeg{start, end})
		pos = end
	}
	for range rng.IntN(len(segs) + 1) {
		s := segs[rng.IntN(len(segs))]
		if rng.IntN(2) == 0 {
			segs = append(segs, s) // duplicate
			continue
		}
		start := s.start + rng.IntN(s.end-s.start)
		segs = append(segs, testSeg{start, start + 1 + rng.IntN(s.end-start)})
	}
	return segs
}

// arrivalOrder shuffles segs while keeping at most maxOOOSegments of them
// waiting behind a gap, so the reassembler never has cause to skip one.
// The earliest remaining segment always reaches the contiguous prefix, so
// some segment is always eligible.
func arrivalOrder(rng *rand.Rand, segs []testSeg) []testSeg {
	remaining := slices.Clone(segs)
	var order, waiting []testSeg
	next := 0
	for len(remaining) > 0 {
		var eligible []int
		for i, s := range remaining {
			if s.start <= next || len(waiting) < maxOOOSegments {
				eligible = append(eligible, i)
			}
		}
		i := eligible[rng.IntN(len(eligible))]
		s := remaining[i]
		remaining = slices.Delete(remaining, i, i+1)
		order = append(order, s)
		if s.start > next {
			waiting = append(waiting, s)
			continue
		}
		next = max(next, s.end)
		for absorbed := true; absorbed; {
			absorbed = false
			for j, w := range waiting {
				if w.start <= next {
					next = max(next, w.end)
					waiting = slices.Delete(waiting, j, j+1)
					absorbed = true
					break
				}
			}
		}
	}
	return order
}

func TestFeedShuffledOverlappingSegmentsLoseNoByte(t *testing.T) {
	rng := rand.New(rand.NewPCG(1, 2))
	for trial := range 2000 {
		n := 1 + rng.IntN(300)
		data := seqBytes(n)
		base := rng.Uint32()
		if trial%4 == 0 {
			base = 0xFFFFFFFF - uint32(rng.IntN(n+16)) // wrap inside the stream
		}
		order := arrivalOrder(rng, overlappingCover(rng, n))

		r := NewReassembler(0, time.Minute)
		now := time.Now()
		r.Open("flow1", base, now)
		var buf []byte
		for _, s := range order {
			buf = r.Feed("flow1", data[s.start:s.end], now, base+uint32(s.start), true)
			if !bytes.HasPrefix(data, buf) {
				t.Fatalf("trial %d: stream %x diverges from %x (order %v)", trial, buf, data, order)
			}
		}
		if !bytes.Equal(buf, data) {
			t.Fatalf("trial %d: got %x, want %x (base %#x, order %v)", trial, buf, data, base, order)
		}
	}
}

// mockStreamDecoder frames a simple protocol: the first byte is the
// message length, followed by that many bytes of payload.
type mockStreamDecoder struct{}

func (m *mockStreamDecoder) Supports(_ *flow.State) bool { return true }

func (m *mockStreamDecoder) OnPacket(_ *flow.State, _ *ParsedPacket) ([]Event, error) {
	return nil, nil
}

func (m *mockStreamDecoder) OnFlowEnd(_ *flow.State) ([]Event, error) { return nil, nil }

func (m *mockStreamDecoder) DecodeStream(_ *flow.State, stream []byte) ([]Event, int) {
	var events []Event
	off := 0
	for off < len(stream) {
		msgLen := int(stream[off])
		if len(stream)-off < 1+msgLen {
			break
		}
		events = append(events, Event{Kind: "test-frame", Proto: "tcp", Attributes: map[string]any{"msg": stream[off+1 : off+1+msgLen]}})
		off += 1 + msgLen
	}
	return events, off
}

func tcpSeg(seq uint32, payload ...byte) *ParsedPacket {
	return &ParsedPacket{Proto: "tcp", Payload: payload, TCPSeq: seq, HasTCPSeq: true}
}

func TestIntegrationReassemblyWithStreamDecoder(t *testing.T) {
	mgr := NewManager(&mockStreamDecoder{})
	st := flow.NewState(flow.Key{}, time.Now())

	// Frame: length=3, payload=0xAA 0xBB 0xCC, split across two segments.
	if events, _ := mgr.OnPacket(st, tcpSeg(1000, 0x03, 0xAA)); len(events) != 0 {
		t.Fatalf("segment 1: expected 0 events (incomplete), got %d", len(events))
	}
	events, err := mgr.OnPacket(st, tcpSeg(1002, 0xBB, 0xCC))
	if err != nil {
		t.Fatalf("segment 2: %v", err)
	}
	if len(events) != 1 || events[0].Kind != "test-frame" {
		t.Fatalf("segment 2: expected 1 test-frame event, got %+v", events)
	}
	// The consumed frame is trimmed: the next segment decodes on its own.
	if events, _ := mgr.OnPacket(st, tcpSeg(1004, 0x01, 0xFF)); len(events) != 1 {
		t.Fatalf("segment 3: expected 1 event (complete 1-byte frame), got %d", len(events))
	}
}

func TestManagerDecodesEachStreamFrameOnce(t *testing.T) {
	mgr := NewManager(&mockStreamDecoder{})
	st := flow.NewState(flow.Key{}, time.Now())

	// Two frames coalesced in one segment plus the start of a third.
	events, _ := mgr.OnPacket(st, tcpSeg(0, 0x01, 0x0A, 0x01, 0x0B, 0x02, 0x0C))
	if len(events) != 2 {
		t.Fatalf("coalesced: expected 2 events, got %d", len(events))
	}
	// The same segment captured again (retransmission or the second
	// interface of a forwarded packet) yields nothing new.
	if events, _ := mgr.OnPacket(st, tcpSeg(0, 0x01, 0x0A, 0x01, 0x0B, 0x02, 0x0C)); len(events) != 0 {
		t.Fatalf("retransmission: expected 0 events, got %d", len(events))
	}
	// The tail completes the third frame.
	events, _ = mgr.OnPacket(st, tcpSeg(6, 0x0D))
	if len(events) != 1 || !bytes.Equal(events[0].Attributes["msg"].([]byte), []byte{0x0C, 0x0D}) {
		t.Fatalf("tail: expected frame 0c0d, got %+v", events)
	}
}

func TestManagerSYNResetsStream(t *testing.T) {
	mgr := NewManager(&mockStreamDecoder{})
	st := flow.NewState(flow.Key{}, time.Now())

	mgr.OnPacket(st, tcpSeg(5000, 0x01, 0x0A))
	// A new connection on the same tuple starts a sequence space that
	// sits "behind" the old one; without the SYN it would look like a
	// retransmission and never be decoded.
	mgr.OnPacket(st, &ParsedPacket{Proto: "tcp", TCPSeq: 100, HasTCPSeq: true, TCPSyn: true})
	if events, _ := mgr.OnPacket(st, tcpSeg(100, 0x01, 0x0B)); len(events) != 1 {
		t.Fatalf("after SYN: expected 1 event, got %d", len(events))
	}
}

// TestManagerLateSYNCopyKeepsStream covers AF_PACKET capturing a forwarded
// connection on two interfaces: one goroutine can process SYN and data
// before the other processes its copy of the SYN. That late copy must not
// reset the stream, or the data is decoded a second time.
func TestManagerLateSYNCopyKeepsStream(t *testing.T) {
	mgr := NewManager(&mockStreamDecoder{})
	st := flow.NewState(flow.Key{}, time.Now())
	syn := &ParsedPacket{Proto: "tcp", TCPSeq: 100, HasTCPSeq: true, TCPSyn: true}

	total := 0
	for _, p := range []*ParsedPacket{syn, tcpSeg(100, 0x01, 0x0A), syn, tcpSeg(100, 0x01, 0x0A), tcpSeg(102, 0x01, 0x0B)} {
		events, _ := mgr.OnPacket(st, p)
		total += len(events)
	}
	if total != 2 {
		t.Fatalf("expected 2 events, got %d", total)
	}
}

func TestManagerConcurrentCapturesDecodeOnce(t *testing.T) {
	mgr := NewManager(&mockStreamDecoder{})
	st := flow.NewState(flow.Key{}, time.Now())

	const frames = 200
	var wg sync.WaitGroup
	var mu sync.Mutex
	total := 0
	// Two capture goroutines see every segment, as AF_PACKET does for a
	// forwarded packet on its ingress and egress interface.
	for range 2 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := range frames {
				events, _ := mgr.OnPacket(st, tcpSeg(uint32(i*2), 0x01, byte(i)))
				mu.Lock()
				total += len(events)
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
	if total != frames {
		t.Fatalf("expected %d events, got %d", frames, total)
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

func TestPacketDecodersSeeSegmentsOnTCP(t *testing.T) {
	dec := &mockDecoder{support: true}
	mgr := NewManager(dec)

	st := flow.NewState(flow.Key{}, time.Now())
	if _, err := mgr.OnPacket(st, tcpSeg(1, 0x01)); err != nil {
		t.Fatalf("tcp: %v", err)
	}
	if dec.calls != 1 || mgr.reassembler.ActiveStreams != 0 {
		t.Fatalf("packet decoder: calls=%d streams=%d, want 1 call and no stream", dec.calls, mgr.reassembler.ActiveStreams)
	}
}
