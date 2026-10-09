// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

package dpi

import (
	"sync"
	"time"

	"github.com/tonylturner/containd/pkg/dp/flow"
)

const (
	defaultMaxStreamSize = 64 * 1024 // 64 KB
	maxOOOSegments       = 4         // max out-of-order segments per stream
)

// StreamDecoder is implemented by decoders of framed TCP protocols. The
// Manager feeds them the reassembled, in-order byte stream of one flow
// direction instead of individual segments.
type StreamDecoder interface {
	Decoder
	// DecodeStream returns one event per complete message at the start of
	// stream and the number of leading bytes those messages occupy. An
	// incomplete trailing message stays unconsumed until more data
	// arrives. Bytes that can never be framed are reported as consumed
	// (up to len(stream)) so the stream is discarded rather than wedged.
	// Implementations keep no per-call state: one decoder instance serves
	// every flow, and the consumed count is the only result the Manager
	// trims by.
	DecodeStream(state *flow.State, stream []byte) (events []Event, consumed int)
}

// oooSegment holds a single out-of-order TCP segment.
type oooSegment struct {
	seq     uint32
	payload []byte
}

// StreamBuffer holds the accumulated TCP payload for a single flow.
type StreamBuffer struct {
	flowKey    string
	buf        []byte
	maxSize    int
	lastUpdate time.Time

	// Sequence tracking for out-of-order handling.
	seqTracking bool   // true once first seq is seen
	nextSeq     uint32 // expected next sequence number
	retransmits uint64 // count of retransmitted segments
	synSeen     bool   // the stream was opened by a SYN
	synSeq      uint32 // sequence number following that SYN

	// Small bounded buffer of out-of-order segments.
	ooo []oooSegment
}

// Reassembler collects TCP payloads per flow so that DPI decoders can
// inspect data that spans multiple segments.
type Reassembler struct {
	mu          sync.Mutex
	streams     map[string]*StreamBuffer
	maxSize     int
	idleTimeout time.Duration

	// Stats – protected by mu.
	ActiveStreams int
	BytesBuffered int
}

// NewReassembler creates a Reassembler.  maxStreamSize caps individual
// stream buffers (0 means 64 KB default).  idleTimeout controls when
// Sweep evicts stale streams.
func NewReassembler(maxStreamSize int, idleTimeout time.Duration) *Reassembler {
	if maxStreamSize <= 0 {
		maxStreamSize = defaultMaxStreamSize
	}
	return &Reassembler{
		streams:     make(map[string]*StreamBuffer),
		maxSize:     maxStreamSize,
		idleTimeout: idleTimeout,
	}
}

// seqDiff returns the signed distance from a to b in the TCP sequence
// number space, handling 32-bit wrap-around.  Positive means b is ahead
// of a.
func seqDiff(a, b uint32) int32 {
	return int32(b - a)
}

// Feed appends payload to the stream buffer identified by flowKey and
// returns the full accumulated in-order buffer. If the buffer would exceed
// maxSize, the oldest bytes are discarded (sliding window).
//
// seq is the TCP sequence number of payload's first byte and is used only
// when hasSeq is set; zero is a valid sequence number. Segments with a
// sequence number are deduplicated (retransmissions, the second capture of
// a forwarded segment) and reordered. Segments without one are appended in
// arrival order.
func (r *Reassembler) Feed(flowKey string, payload []byte, now time.Time, seq uint32, hasSeq bool) []byte {
	r.mu.Lock()
	defer r.mu.Unlock()

	sb, ok := r.streams[flowKey]
	if !ok {
		sb = &StreamBuffer{
			flowKey: flowKey,
			maxSize: r.maxSize,
			buf:     make([]byte, 0, min(len(payload)*4, r.maxSize)),
		}
		r.streams[flowKey] = sb
		r.ActiveStreams++
	}

	sb.lastUpdate = now
	before := len(sb.buf)

	switch {
	case !hasSeq:
		sb.buf = append(sb.buf, payload...)
		sb.nextSeq += uint32(len(payload))
	case !sb.seqTracking:
		// The first sequenced segment anchors the stream.
		sb.seqTracking = true
		sb.buf = append(sb.buf, payload...)
		sb.nextSeq = seq + uint32(len(payload))
	default:
		r.feedSequenced(sb, payload, seq)
	}

	// Sliding window: drop oldest bytes when over limit.
	if len(sb.buf) > sb.maxSize {
		sb.buf = sb.buf[len(sb.buf)-sb.maxSize:]
	}
	r.BytesBuffered += len(sb.buf) - before
	if r.BytesBuffered < 0 {
		r.BytesBuffered = 0
	}

	// Return a copy so callers cannot mutate internal state.
	out := make([]byte, len(sb.buf))
	copy(out, sb.buf)
	return out
}

// feedSequenced places a segment relative to the expected sequence number.
// Must be called with r.mu held.
func (r *Reassembler) feedSequenced(sb *StreamBuffer, payload []byte, seq uint32) {
	diff := seqDiff(sb.nextSeq, seq)
	switch {
	case diff == 0:
		sb.buf = append(sb.buf, payload...)
		sb.nextSeq = seq + uint32(len(payload))
		r.flushOOO(sb)
	case diff > 0:
		// Future segment: a gap precedes it.
		if len(sb.ooo) >= maxOOOSegments {
			// The gap outlived maxOOOSegments later segments, so the
			// missing bytes were lost (for example a capture drop).
			// Resynchronise at the earliest buffered segment instead of
			// stalling the stream forever; the partial message before
			// the gap can never complete.
			r.skipGap(sb)
			r.feedSequenced(sb, payload, seq)
			return
		}
		seg := oooSegment{seq: seq, payload: make([]byte, len(payload))}
		copy(seg.payload, payload)
		sb.ooo = insertOOO(sb.ooo, seg)
	default:
		// seq is behind nextSeq: a retransmission. Keep only bytes past
		// nextSeq, if the segment carries any.
		endSeq := seq + uint32(len(payload))
		if seqDiff(sb.nextSeq, endSeq) <= 0 {
			sb.retransmits++
			return
		}
		overlap := int(seqDiff(seq, sb.nextSeq))
		sb.buf = append(sb.buf, payload[overlap:]...)
		sb.nextSeq = endSeq
		r.flushOOO(sb)
	}
}

// skipGap discards the buffered bytes before a lost gap and moves the
// stream to the earliest out-of-order segment. Must be called with r.mu
// held.
func (r *Reassembler) skipGap(sb *StreamBuffer) {
	sb.buf = sb.buf[:0]
	sb.nextSeq = sb.ooo[0].seq
	r.flushOOO(sb)
}

// flushOOO drains any contiguous OOO segments that now fit at nextSeq.
// Must be called with r.mu held.
func (r *Reassembler) flushOOO(sb *StreamBuffer) {
	for i := 0; i < len(sb.ooo); {
		seg := sb.ooo[i]
		diff := seqDiff(sb.nextSeq, seg.seq)
		if diff == 0 {
			// This segment is now in-order.
			sb.buf = append(sb.buf, seg.payload...)
			sb.nextSeq = seg.seq + uint32(len(seg.payload))
			// Remove from OOO buffer.
			sb.ooo = append(sb.ooo[:i], sb.ooo[i+1:]...)
			// Restart scan — a later segment may now be contiguous.
			i = 0
			continue
		}
		if diff < 0 {
			// This segment is now behind nextSeq (already covered).
			sb.ooo = append(sb.ooo[:i], sb.ooo[i+1:]...)
			continue
		}
		i++
	}
}

// insertOOO inserts a segment into the OOO slice sorted by sequence number.
func insertOOO(ooo []oooSegment, seg oooSegment) []oooSegment {
	for i, s := range ooo {
		if seqDiff(seg.seq, s.seq) > 0 {
			// Insert before s.
			ooo = append(ooo, oooSegment{})
			copy(ooo[i+1:], ooo[i:])
			ooo[i] = seg
			return ooo
		}
		if s.seq == seg.seq {
			// Duplicate — skip.
			return ooo
		}
	}
	return append(ooo, seg)
}

// Retransmissions returns the retransmission count for the given flow.
func (r *Reassembler) Retransmissions(flowKey string) uint64 {
	r.mu.Lock()
	defer r.mu.Unlock()
	if sb, ok := r.streams[flowKey]; ok {
		return sb.retransmits
	}
	return 0
}

// Trim removes the first n consumed bytes from the stream buffer for the
// given flow.  Decoders call this (via the Manager) after successfully
// parsing a complete message.
func (r *Reassembler) Trim(flowKey string, n int) {
	r.mu.Lock()
	defer r.mu.Unlock()

	sb, ok := r.streams[flowKey]
	if !ok || n <= 0 {
		return
	}
	if n >= len(sb.buf) {
		r.BytesBuffered -= len(sb.buf)
		sb.buf = sb.buf[:0]
	} else {
		r.BytesBuffered -= n
		sb.buf = sb.buf[n:]
	}
	if r.BytesBuffered < 0 {
		r.BytesBuffered = 0
	}
}

// Open starts the stream of a new connection direction at a SYN. seq is
// the sequence number of the first byte after the SYN. The same SYN seen
// again (a retransmission, or its capture on a second interface arriving
// after the data that followed it) leaves the stream as it is; a SYN with
// a different sequence number replaces whatever an earlier connection on
// the same tuple left behind.
func (r *Reassembler) Open(flowKey string, seq uint32, now time.Time) {
	r.mu.Lock()
	defer r.mu.Unlock()

	if sb, ok := r.streams[flowKey]; ok {
		if sb.synSeen && sb.synSeq == seq {
			return
		}
		r.BytesBuffered = max(r.BytesBuffered-len(sb.buf), 0)
	} else {
		r.ActiveStreams++
	}
	r.streams[flowKey] = &StreamBuffer{
		flowKey:     flowKey,
		maxSize:     r.maxSize,
		lastUpdate:  now,
		seqTracking: true,
		nextSeq:     seq,
		synSeen:     true,
		synSeq:      seq,
	}
}

// Complete removes the stream buffer for the given flow (e.g. when the
// connection ends or a message has been fully parsed and no residual data
// remains).
func (r *Reassembler) Complete(flowKey string) {
	r.mu.Lock()
	defer r.mu.Unlock()

	if sb, ok := r.streams[flowKey]; ok {
		r.BytesBuffered -= len(sb.buf)
		if r.BytesBuffered < 0 {
			r.BytesBuffered = 0
		}
		delete(r.streams, flowKey)
		r.ActiveStreams--
	}
}

// Sweep removes streams that have been idle longer than idleTimeout.
func (r *Reassembler) Sweep(now time.Time) {
	r.mu.Lock()
	defer r.mu.Unlock()

	for key, sb := range r.streams {
		if now.Sub(sb.lastUpdate) > r.idleTimeout {
			r.BytesBuffered -= len(sb.buf)
			delete(r.streams, key)
			r.ActiveStreams--
		}
	}
	if r.BytesBuffered < 0 {
		r.BytesBuffered = 0
	}
}
