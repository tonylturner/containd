// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

package dpi

import (
	"sync"
	"time"
)

const (
	defaultMaxStreamSize = 64 * 1024 // 64 KB
	maxOOOSegments       = 4         // max out-of-order segments per stream
)

// StreamDecoder is an optional interface that stream-aware decoders can
// implement.  After a successful parse the reassembler uses ConsumedBytes
// to trim already-processed data from the buffer instead of discarding the
// entire stream.
type StreamDecoder interface {
	Decoder
	// ConsumedBytes returns the number of leading bytes that were
	// successfully parsed in the last OnPacket call.  Return 0 if the
	// buffer does not yet contain a complete message.
	ConsumedBytes() int
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
	ActiveStreams  int
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
// returns the full accumulated buffer.  If the buffer would exceed
// maxSize, the oldest bytes are discarded (sliding window).
//
// The seq parameter is the TCP sequence number of this segment.  If seq
// is 0 and no sequence tracking has been established, it is treated as
// in-order (legacy callers).
func (r *Reassembler) Feed(flowKey string, payload []byte, now time.Time, seq uint32) []byte {
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

	// Establish sequence tracking on first segment with a non-zero seq,
	// or if seq is provided on a new stream.
	if !sb.seqTracking {
		sb.seqTracking = true
		sb.nextSeq = seq + uint32(len(payload))
		sb.buf = append(sb.buf, payload...)
	} else {
		diff := seqDiff(sb.nextSeq, seq)
		switch {
		case diff == 0:
			// In-order segment.
			sb.buf = append(sb.buf, payload...)
			sb.nextSeq = seq + uint32(len(payload))
			// Try to flush any buffered OOO segments.
			r.flushOOO(sb)
		case diff > 0:
			// Future segment — gap detected. Buffer it if we have room.
			if len(sb.ooo) < maxOOOSegments {
				// Insert sorted by seq.
				seg := oooSegment{seq: seq, payload: make([]byte, len(payload))}
				copy(seg.payload, payload)
				sb.ooo = insertOOO(sb.ooo, seg)
			}
			// If OOO buffer is full, drop this segment (bounded memory).
		default:
			// diff < 0: seq is behind nextSeq — likely retransmission.
			// Check for partial overlap: if seq + len(payload) > nextSeq,
			// there is new data at the tail.
			endSeq := seq + uint32(len(payload))
			newDiff := seqDiff(sb.nextSeq, endSeq)
			if newDiff > 0 {
				// Partial overlap — extract the new portion.
				overlap := int(seqDiff(seq, sb.nextSeq))
				if overlap >= 0 && overlap < len(payload) {
					newData := payload[overlap:]
					sb.buf = append(sb.buf, newData...)
					sb.nextSeq = endSeq
					r.flushOOO(sb)
				}
			}
			// Pure retransmission — skip.
			sb.retransmits++
		}
	}

	// Sliding window: drop oldest bytes when over limit.
	if len(sb.buf) > sb.maxSize {
		excess := len(sb.buf) - sb.maxSize
		r.BytesBuffered -= excess
		sb.buf = sb.buf[excess:]
	}

	r.BytesBuffered += len(payload)
	// Clamp in case of rounding from the trim above.
	if r.BytesBuffered < 0 {
		r.BytesBuffered = 0
	}

	// Return a copy so callers cannot mutate internal state.
	out := make([]byte, len(sb.buf))
	copy(out, sb.buf)
	return out
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
