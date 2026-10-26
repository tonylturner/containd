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

func TestMainFeedAccumulatesData(t *testing.T) {
	r := newReassembler(0, time.Minute)
	now := time.Now()

	buf1 := r.feed("flow1", position{kind: posSeq, seq: 100}, []byte{0x01, 0x02}, now, false, false, false).buf
	if !bytes.Equal(buf1, []byte{0x01, 0x02}) {
		t.Fatalf("first feed: got %x, want 0102", buf1)
	}

	buf2 := r.feed("flow1", position{kind: posSeq, seq: 102}, []byte{0x03, 0x04}, now, false, false, false).buf
	if !bytes.Equal(buf2, []byte{0x01, 0x02, 0x03, 0x04}) {
		t.Fatalf("second feed: got %x, want 01020304", buf2)
	}

	if r.activeStreams != 1 {
		t.Fatalf("active streams: got %d, want 1", r.activeStreams)
	}
	if r.bytesBuffered != 4 {
		t.Fatalf("bytes buffered: got %d, want 4", r.bytesBuffered)
	}
}

func TestMainFeedSlidingWindow(t *testing.T) {
	// maxSize = 4 bytes
	r := newReassembler(4, time.Minute)
	now := time.Now()

	r.feed("flow1", position{kind: posSeq, seq: 100}, []byte{0x01, 0x02, 0x03}, now, false, false, false)
	buf := r.feed("flow1", position{kind: posSeq, seq: 103}, []byte{0x04, 0x05, 0x06}, now, false, false, false).buf

	// 6 bytes total, max 4 -> oldest 2 bytes discarded
	want := []byte{0x03, 0x04, 0x05, 0x06}
	if !bytes.Equal(buf, want) {
		t.Fatalf("sliding window: got %x, want %x", buf, want)
	}
}

func TestMainCompleteRemovesStream(t *testing.T) {
	r := newReassembler(0, time.Minute)
	now := time.Now()

	r.feed("flow1", position{kind: posSeq, seq: 100}, []byte{0x01}, now, false, false, false)
	r.feed("flow2", position{kind: posSeq, seq: 200}, []byte{0x02}, now, false, false, false)

	if r.activeStreams != 2 {
		t.Fatalf("before complete: active=%d, want 2", r.activeStreams)
	}

	r.complete("flow1")
	if r.activeStreams != 1 {
		t.Fatalf("after complete: active=%d, want 1", r.activeStreams)
	}

	// Feed to flow1 again should start fresh.
	buf := r.feed("flow1", position{kind: posSeq, seq: 300}, []byte{0xAA}, now, false, false, false).buf
	if !bytes.Equal(buf, []byte{0xAA}) {
		t.Fatalf("after complete+feed: got %x, want aa", buf)
	}
}

func TestMainSweepRemovesIdleStreams(t *testing.T) {
	r := newReassembler(0, 5*time.Second)
	t0 := time.Now()

	r.feed("flow1", position{kind: posSeq, seq: 100}, []byte{0x01}, t0, false, false, false)
	r.feed("flow2", position{kind: posSeq, seq: 200}, []byte{0x02}, t0.Add(4*time.Second), false, false, false)

	// At t0+6s, flow1 is 6s idle (>5s), flow2 is 2s idle (<5s).
	r.sweep(t0.Add(6 * time.Second))

	if r.activeStreams != 1 {
		t.Fatalf("after sweep: active=%d, want 1", r.activeStreams)
	}

	// Verify flow2 still works.
	buf := r.feed("flow2", position{kind: posSeq, seq: 201}, []byte{0x03}, t0.Add(6*time.Second), false, false, false).buf
	if !bytes.Equal(buf, []byte{0x02, 0x03}) {
		t.Fatalf("flow2 after sweep: got %x, want 0203", buf)
	}
}

func TestMainTrimConsumedBytes(t *testing.T) {
	r := newReassembler(0, time.Minute)
	now := time.Now()

	r.feed("flow1", position{kind: posSeq, seq: 100}, []byte{0x01, 0x02, 0x03, 0x04, 0x05}, now, false, false, false)
	r.trim("flow1", 0, 3)

	buf := r.feed("flow1", position{kind: posSeq, seq: 105}, []byte{0x06}, now, false, false, false).buf
	want := []byte{0x04, 0x05, 0x06}
	if !bytes.Equal(buf, want) {
		t.Fatalf("after trim+feed: got %x, want %x", buf, want)
	}
}

func TestMainFeedOutOfOrder(t *testing.T) {
	r := newReassembler(0, time.Minute)
	now := time.Now()

	// Send segment 1 (seq=100, 2 bytes).
	r.feed("flow1", position{kind: posSeq, seq: 100}, []byte{0x01, 0x02}, now, false, false, false)

	// Send segment 3 (seq=105, 2 bytes) — skipping segment 2.
	buf := r.feed("flow1", position{kind: posSeq, seq: 105}, []byte{0x05, 0x06}, now, false, false, false).buf
	// Should only have segment 1 data; segment 3 is buffered OOO.
	if !bytes.Equal(buf, []byte{0x01, 0x02}) {
		t.Fatalf("after OOO: got %x, want 0102", buf)
	}

	// Send segment 2 (seq=102, 3 bytes) — fills the gap.
	buf = r.feed("flow1", position{kind: posSeq, seq: 102}, []byte{0x03, 0x04, 0x77}, now, false, false, false).buf
	// Now all three segments should be flushed in order.
	want := []byte{0x01, 0x02, 0x03, 0x04, 0x77, 0x05, 0x06}
	if !bytes.Equal(buf, want) {
		t.Fatalf("after gap fill: got %x, want %x", buf, want)
	}
}

func TestMainFeedRetransmission(t *testing.T) {
	r := newReassembler(0, time.Minute)
	now := time.Now()

	// Send segment 1.
	r.feed("flow1", position{kind: posSeq, seq: 100}, []byte{0x01, 0x02}, now, false, false, false)
	// Retransmit segment 1.
	buf := r.feed("flow1", position{kind: posSeq, seq: 100}, []byte{0x01, 0x02}, now, false, false, false).buf
	// Should still have only 2 bytes.
	if !bytes.Equal(buf, []byte{0x01, 0x02}) {
		t.Fatalf("after retransmit: got %x, want 0102", buf)
	}

	retrans := r.retransmissions("flow1")
	if retrans != 1 {
		t.Fatalf("retransmissions: got %d, want 1", retrans)
	}
}

func TestMainFeedSequenceZeroIsTracked(t *testing.T) {
	r := newReassembler(0, time.Minute)
	now := time.Now()

	r.feed("flow1", position{kind: posSeq, seq: 0}, []byte{0x01, 0x02}, now, false, false, false)
	// A retransmission at seq 0 must not be appended again.
	if buf := r.feed("flow1", position{kind: posSeq, seq: 0}, []byte{0x01, 0x02}, now, false, false, false).buf; !bytes.Equal(buf, []byte{0x01, 0x02}) {
		t.Fatalf("seq 0 retransmission appended: %x", buf)
	}
	if buf := r.feed("flow1", position{kind: posSeq, seq: 2}, []byte{0x03}, now, false, false, false).buf; !bytes.Equal(buf, []byte{0x01, 0x02, 0x03}) {
		t.Fatalf("segment after seq 0: got %x", buf)
	}
}

func TestMainFeedSequenceWrap(t *testing.T) {
	r := newReassembler(0, time.Minute)
	now := time.Now()

	r.feed("flow1", position{kind: posSeq, seq: 0xFFFFFFFE}, []byte{0x01, 0x02}, now, false, false, false)
	buf := r.feed("flow1", position{kind: posSeq, seq: 0}, []byte{0x03, 0x04}, now, false, false, false).buf
	if !bytes.Equal(buf, []byte{0x01, 0x02, 0x03, 0x04}) {
		t.Fatalf("across wrap: got %x", buf)
	}
	// Retransmission of the pre-wrap segment.
	buf = r.feed("flow1", position{kind: posSeq, seq: 0xFFFFFFFE}, []byte{0x01, 0x02}, now, false, false, false).buf
	if !bytes.Equal(buf, []byte{0x01, 0x02, 0x03, 0x04}) {
		t.Fatalf("pre-wrap retransmission appended: %x", buf)
	}
}

func TestMainFeedWithoutSequenceAppends(t *testing.T) {
	r := newReassembler(0, time.Minute)
	now := time.Now()

	r.feed("flow1", position{kind: posAppend}, []byte{0x01}, now, false, false, false)
	buf := r.feed("flow1", position{kind: posAppend}, []byte{0x01}, now, false, false, false).buf
	if !bytes.Equal(buf, []byte{0x01, 0x01}) {
		t.Fatalf("unsequenced segments: got %x, want 0101", buf)
	}
}

func TestMainFeedPartialRetransmission(t *testing.T) {
	r := newReassembler(0, time.Minute)
	now := time.Now()

	// Send 3 bytes at seq 100.
	r.feed("flow1", position{kind: posSeq, seq: 100}, []byte{0x01, 0x02, 0x03}, now, false, false, false)

	// Send overlapping segment: seq 101, 4 bytes — 2 bytes overlap, 2 new.
	buf := r.feed("flow1", position{kind: posSeq, seq: 101}, []byte{0x02, 0x03, 0x04, 0x05}, now, false, false, false).buf
	want := []byte{0x01, 0x02, 0x03, 0x04, 0x05}
	if !bytes.Equal(buf, want) {
		t.Fatalf("partial retransmit: got %x, want %x", buf, want)
	}
}

// mainSeqBytes returns n bytes whose values follow their offset, so a lost,
// duplicated or misplaced byte shows up in a comparison.
func mainSeqBytes(n int) []byte {
	out := make([]byte, n)
	for i := range out {
		out[i] = byte(i*7 + i/256)
	}
	return out
}

func TestMainFeedQueuedSegmentTailPastNextSeq(t *testing.T) {
	r := newReassembler(0, time.Minute)
	now := time.Now()
	data := mainSeqBytes(40) // seq 100..140

	r.open("flow1", 100, now)
	r.feed("flow1", position{kind: posSeq, seq: 120}, data[20:40], now, false, false, false)
	// 100..130 overlaps the queued 120..140; its tail 130..140 must still
	// be appended.
	buf := r.feed("flow1", position{kind: posSeq, seq: 100}, data[0:30], now, false, false, false).buf
	if !bytes.Equal(buf, data) {
		t.Fatalf("got %x, want %x", buf, data)
	}
}

func TestMainFeedOOOSameSeqKeepsLongerCopy(t *testing.T) {
	r := newReassembler(0, time.Minute)
	now := time.Now()
	data := mainSeqBytes(40)

	r.open("flow1", 100, now)
	r.feed("flow1", position{kind: posSeq, seq: 120}, data[20:25], now, false, false, false)
	r.feed("flow1", position{kind: posSeq, seq: 120}, data[20:40], now, false, false, false)
	// A shorter copy arriving after the longer one adds nothing.
	r.feed("flow1", position{kind: posSeq, seq: 120}, data[20:30], now, false, false, false)
	buf := r.feed("flow1", position{kind: posSeq, seq: 100}, data[0:20], now, false, false, false).buf
	if !bytes.Equal(buf, data) {
		t.Fatalf("got %x, want %x", buf, data)
	}
}

func TestMainFeedOOOPartialAndContainedOverlaps(t *testing.T) {
	r := newReassembler(0, time.Minute)
	now := time.Now()
	data := mainSeqBytes(60)

	r.open("flow1", 100, now)
	r.feed("flow1", position{kind: posSeq, seq: 120}, data[20:40], now, false, false, false) // queued
	r.feed("flow1", position{kind: posSeq, seq: 130}, data[30:50], now, false, false, false) // overlaps its tail
	r.feed("flow1", position{kind: posSeq, seq: 115}, data[15:25], now, false, false, false) // overlaps its head
	r.feed("flow1", position{kind: posSeq, seq: 132}, data[32:38], now, false, false, false) // contained in a queued one
	r.feed("flow1", position{kind: posSeq, seq: 150}, data[50:60], now, false, false, false) // adjacent
	buf := r.feed("flow1", position{kind: posSeq, seq: 100}, data[0:15], now, false, false, false).buf
	if !bytes.Equal(buf, data) {
		t.Fatalf("got %x, want %x", buf, data)
	}
}

func TestMainFeedOOOCoveringSegmentReplacesQueued(t *testing.T) {
	r := newReassembler(0, time.Minute)
	now := time.Now()
	data := mainSeqBytes(10 + 2*maxOOOSegments)

	r.open("flow1", 100, now)
	for i := 0; i < maxOOOSegments; i++ {
		off := 10 + 2*i
		r.feed("flow1", position{kind: posSeq, seq: uint32(100 + off)}, data[off:off+1], now, false, false, false)
	}
	// One segment covering every queued one frees their slots, so the
	// next out-of-order segment must not be taken for a lost gap.
	r.feed("flow1", position{kind: posSeq, seq: 110}, data[10:10+2*maxOOOSegments], now, false, false, false)
	r.feed("flow1", position{kind: posSeq, seq: 130}, data[30:40], now, false, false, false)
	r.feed("flow1", position{kind: posSeq, seq: 120}, data[20:30], now, false, false, false)
	buf := r.feed("flow1", position{kind: posSeq, seq: 100}, data[0:10], now, false, false, false).buf
	if !bytes.Equal(buf, data) {
		t.Fatalf("got %x, want %x", buf, data)
	}
}

type mainTestSeg struct{ start, end int }

// mainOverlappingCover returns segments covering [0, n) with overlaps,
// duplicates and segments contained in others.
func mainOverlappingCover(rng *rand.Rand, n int) []mainTestSeg {
	var segs []mainTestSeg
	for pos := 0; pos < n; {
		start := max(0, pos-rng.IntN(16))
		end := min(n, pos+1+rng.IntN(32))
		segs = append(segs, mainTestSeg{start, end})
		pos = end
	}
	for range rng.IntN(len(segs) + 1) {
		s := segs[rng.IntN(len(segs))]
		if rng.IntN(2) == 0 {
			segs = append(segs, s) // duplicate
			continue
		}
		start := s.start + rng.IntN(s.end-s.start)
		segs = append(segs, mainTestSeg{start, start + 1 + rng.IntN(s.end-start)})
	}
	return segs
}

// mainArrivalOrder shuffles segs while keeping at most maxOOOSegments of them
// waiting behind a gap, so the reassembler never has cause to skip one.
// The earliest remaining segment always reaches the contiguous prefix, so
// some segment is always eligible.
func mainArrivalOrder(rng *rand.Rand, segs []mainTestSeg) []mainTestSeg {
	remaining := slices.Clone(segs)
	var order, waiting []mainTestSeg
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

func TestMainFeedShuffledOverlappingSegmentsLoseNoByte(t *testing.T) {
	rng := rand.New(rand.NewPCG(1, 2))
	for trial := range 2000 {
		n := 1 + rng.IntN(300)
		data := mainSeqBytes(n)
		base := rng.Uint32()
		if trial%4 == 0 {
			base = 0xFFFFFFFF - uint32(rng.IntN(n+16)) // wrap inside the stream
		}
		order := mainArrivalOrder(rng, mainOverlappingCover(rng, n))

		r := newReassembler(0, time.Minute)
		now := time.Now()
		r.open("flow1", base, now)
		var buf []byte
		for _, s := range order {
			buf = r.feed("flow1", position{kind: posSeq, seq: base + uint32(s.start)}, data[s.start:s.end], now, false, false, false).buf
			if !bytes.HasPrefix(data, buf) {
				t.Fatalf("trial %d: stream %x diverges from %x (order %v)", trial, buf, data, order)
			}
		}
		if !bytes.Equal(buf, data) {
			t.Fatalf("trial %d: got %x, want %x (base %#x, order %v)", trial, buf, data, base, order)
		}
	}
}

// mainMockStreamDecoder frames a simple protocol: the first byte is the
// message length, followed by that many bytes of payload.
type mainMockStreamDecoder struct{}

func (m *mainMockStreamDecoder) Supports(_ *flow.State) bool { return true }

func (m *mainMockStreamDecoder) OnPacket(_ *flow.State, _ *ParsedPacket) ([]Event, error) {
	return nil, nil
}

func (m *mainMockStreamDecoder) OnFlowEnd(_ *flow.State) ([]Event, error) { return nil, nil }

func (m *mainMockStreamDecoder) Protocol() string { return "tcp" }
func (m *mainMockStreamDecoder) ParseStream(_ *flow.State, v StreamView) (StreamResult, error) {
	var res StreamResult
	for off := 0; off < len(v.Bytes); {
		n := 1 + int(v.Bytes[off])
		if len(v.Bytes)-off < n {
			res.NeedMore = true
			break
		}
		ev := Event{Kind: "test-frame", Proto: "tcp", Attributes: map[string]any{"msg": append([]byte(nil), v.Bytes[off+1:off+n]...)}}
		res.Frames = append(res.Frames, DecodedFrame{Start: v.Base + int64(off), End: v.Base + int64(off+n), Events: []Event{ev}})
		off += n
		res.Consumed = off
	}
	return res, nil
}

func mainTcpSeg(seq uint32, payload ...byte) *ParsedPacket {
	return &ParsedPacket{Proto: "tcp", Payload: payload, TCPSeq: seq, TCPSeqValid: true}
}

func TestMainIntegrationReassemblyWithStreamDecoder(t *testing.T) {
	mgr := NewManager(&mainMockStreamDecoder{})
	st := flow.NewState(flow.Key{}, time.Now())

	// Frame: length=3, payload=0xAA 0xBB 0xCC, split across two segments.
	if events, _ := mgr.OnPacket(st, mainTcpSeg(1000, 0x03, 0xAA)); len(events) != 0 {
		t.Fatalf("segment 1: expected 0 events (incomplete), got %d", len(events))
	}
	events, err := mgr.OnPacket(st, mainTcpSeg(1002, 0xBB, 0xCC))
	if err != nil {
		t.Fatalf("segment 2: %v", err)
	}
	if len(events) != 1 || events[0].Kind != "test-frame" {
		t.Fatalf("segment 2: expected 1 test-frame event, got %+v", events)
	}
	// The consumed frame is trimmed: the next segment decodes on its own.
	if events, _ := mgr.OnPacket(st, mainTcpSeg(1004, 0x01, 0xFF)); len(events) != 1 {
		t.Fatalf("segment 3: expected 1 event (complete 1-byte frame), got %d", len(events))
	}
}

func TestMainManagerDecodesEachStreamFrameOnce(t *testing.T) {
	mgr := NewManager(&mainMockStreamDecoder{})
	st := flow.NewState(flow.Key{}, time.Now())

	// Two frames coalesced in one segment plus the start of a third.
	events, _ := mgr.OnPacket(st, mainTcpSeg(0, 0x01, 0x0A, 0x01, 0x0B, 0x02, 0x0C))
	if len(events) != 2 {
		t.Fatalf("coalesced: expected 2 events, got %d", len(events))
	}
	// The same segment captured again (retransmission or the second
	// interface of a forwarded packet) yields nothing new.
	if events, _ := mgr.OnPacket(st, mainTcpSeg(0, 0x01, 0x0A, 0x01, 0x0B, 0x02, 0x0C)); len(events) != 0 {
		t.Fatalf("retransmission: expected 0 events, got %d", len(events))
	}
	// The tail completes the third frame.
	events, _ = mgr.OnPacket(st, mainTcpSeg(6, 0x0D))
	if len(events) != 1 || !bytes.Equal(events[0].Attributes["msg"].([]byte), []byte{0x0C, 0x0D}) {
		t.Fatalf("tail: expected frame 0c0d, got %+v", events)
	}
}

func TestMainManagerSYNResetsStream(t *testing.T) {
	mgr := NewManager(&mainMockStreamDecoder{})
	st := flow.NewState(flow.Key{}, time.Now())

	mgr.OnPacket(st, mainTcpSeg(5000, 0x01, 0x0A))
	// A new connection on the same tuple starts a sequence space that
	// sits "behind" the old one; without the SYN it would look like a
	// retransmission and never be decoded.
	mgr.OnPacket(st, &ParsedPacket{Proto: "tcp", TCPSeq: 100, TCPSeqValid: true, TCPSyn: true})
	if events, _ := mgr.OnPacket(st, mainTcpSeg(100, 0x01, 0x0B)); len(events) != 1 {
		t.Fatalf("after SYN: expected 1 event, got %d", len(events))
	}
}

// TestMainManagerLateSYNCopyKeepsStream covers AF_PACKET capturing a forwarded
// connection on two interfaces: one goroutine can process SYN and data
// before the other processes its copy of the SYN. That late copy must not
// reset the stream, or the data is decoded a second time.
func TestMainManagerLateSYNCopyKeepsStream(t *testing.T) {
	mgr := NewManager(&mainMockStreamDecoder{})
	st := flow.NewState(flow.Key{}, time.Now())
	syn := &ParsedPacket{Proto: "tcp", TCPSeq: 100, TCPSeqValid: true, TCPSyn: true}

	total := 0
	for _, p := range []*ParsedPacket{syn, mainTcpSeg(100, 0x01, 0x0A), syn, mainTcpSeg(100, 0x01, 0x0A), mainTcpSeg(102, 0x01, 0x0B)} {
		events, _ := mgr.OnPacket(st, p)
		total += len(events)
	}
	if total != 2 {
		t.Fatalf("expected 2 events, got %d", total)
	}
}

func TestMainManagerConcurrentCapturesDecodeOnce(t *testing.T) {
	mgr := NewManager(&mainMockStreamDecoder{})
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
				events, _ := mgr.OnPacket(st, mainTcpSeg(uint32(i*2), 0x01, byte(i)))
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

func TestMainNonTCPBypassesReassembly(t *testing.T) {
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
	if mgr.reassembler.activeStreams != 0 {
		t.Fatalf("reassembler should have 0 streams for UDP, got %d", mgr.reassembler.activeStreams)
	}
}

func TestMainPacketDecodersSeeSegmentsOnTCP(t *testing.T) {
	dec := &mockDecoder{support: true}
	mgr := NewManager(dec)

	st := flow.NewState(flow.Key{}, time.Now())
	if _, err := mgr.OnPacket(st, mainTcpSeg(1, 0x01)); err != nil {
		t.Fatalf("tcp: %v", err)
	}
	if dec.calls != 1 || mgr.reassembler.activeStreams != 0 {
		t.Fatalf("packet decoder: calls=%d streams=%d, want 1 call and no stream", dec.calls, mgr.reassembler.activeStreams)
	}
}
