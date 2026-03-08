// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

package dpi

import (
	"sync"
	"time"
)

const defaultMaxStreamSize = 64 * 1024 // 64 KB

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

// StreamBuffer holds the accumulated TCP payload for a single flow.
type StreamBuffer struct {
	flowKey    string
	buf        []byte
	maxSize    int
	lastUpdate time.Time
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

// Feed appends payload to the stream buffer identified by flowKey and
// returns the full accumulated buffer.  If the buffer would exceed
// maxSize, the oldest bytes are discarded (sliding window).
func (r *Reassembler) Feed(flowKey string, payload []byte, now time.Time) []byte {
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
	sb.buf = append(sb.buf, payload...)

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
