// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

package dpi

import (
	"bytes"
	"sync"
	"time"
)

const (
	// maxOOOSegments bounds the holes a stream may buffer beyond. It is at
	// least the IEC104 holdback bound of 32 held packets per session, so
	// the reassembler never fails before the engine's own bound.
	maxOOOSegments = 32
)

// posKind says how a segment's position is given.
type posKind uint8

const (
	posAppend posKind = iota // no sequence metadata: arrival order
	posSeq                   // TCP sequence number, relative to the first one seen
	posOffset                // absolute stream offset computed by the caller
)

// position locates one segment in its stream.
type position struct {
	kind posKind
	seq  uint32
	off  int64
}

// oooSegment is buffered data beyond a hole, at absolute offset off.
type oooSegment struct {
	off  int64
	data []byte
}

func (s oooSegment) end() int64 { return s.off + int64(len(s.data)) }

// stream holds the bytes of one TCP stream direction that the manager has
// not consumed yet.
type stream struct {
	// strict streams belong to a framed decoder: buffer bounds, the
	// out-of-order bound and conflicting overlaps are errors. Other streams
	// keep the sliding window (oldest bytes dropped) and ignore conflicts.
	strict bool
	mode   posKind
	seq0   uint32 // posSeq: sequence number of offset 0
	keep   bool   // session stream: lifetime owned by the caller, never idle-swept

	base       int64  // absolute offset of buf[0]; the consumed watermark
	buf        []byte // contiguous bytes from base
	ooo        []oooSegment
	lastUpdate time.Time

	retransmits uint64 // segments that repeated bytes already held or consumed
	failed      error  // session stream failure, until the caller ends it
}

func (s *stream) end() int64 { return s.base + int64(len(s.buf)) }

func (s *stream) stored() int {
	n := len(s.buf)
	for _, seg := range s.ooo {
		n += len(seg.data)
	}
	return n
}

// feedResult is the stream state after one segment.
type feedResult struct {
	buf    []byte // copy of the contiguous bytes from base
	base   int64
	gap    bool // bytes are buffered beyond a hole
	err    *StreamError
	failed error // the stream failed earlier; nothing was fed
}

// reassembler collects TCP payloads per stream direction so that decoders
// can inspect data that spans segments.
type reassembler struct {
	mu          sync.Mutex
	streams     map[string]*stream
	maxSize     int
	idleTimeout time.Duration
	lastSweep   time.Time

	activeStreams int
	bytesBuffered int
}

// newReassembler creates a reassembler. maxStreamSize caps the bytes
// buffered per stream (0 means 64 KB); idleTimeout controls when sweep
// evicts streams that are not session streams.
func newReassembler(maxStreamSize int, idleTimeout time.Duration) *reassembler {
	if maxStreamSize <= 0 {
		maxStreamSize = defaultReassemblyMax
	}
	return &reassembler{
		streams:     make(map[string]*stream),
		maxSize:     maxStreamSize,
		idleTimeout: idleTimeout,
	}
}

// seqDiff returns the signed distance from a to b in the TCP sequence
// number space, handling 32-bit wrap-around. Positive means b is ahead of a.
func seqDiff(a, b uint32) int32 {
	return int32(b - a)
}

// feed adds one segment. A new stream starts at offset 0 in the given
// position mode; strict and keep are fixed at creation.
//
// Bytes below the consumed watermark are duplicates. Bytes the stream
// still holds are compared byte for byte; a difference is a conflict.
func (r *reassembler) feed(key string, pos position, payload []byte, now time.Time, strict, keep bool) feedResult {
	r.mu.Lock()
	defer r.mu.Unlock()

	s, ok := r.streams[key]
	if !ok {
		s = &stream{strict: strict, mode: pos.kind, seq0: pos.seq, keep: keep}
		r.streams[key] = s
		r.activeStreams++
	}
	if s.failed != nil {
		return feedResult{failed: s.failed}
	}
	s.lastUpdate = now
	before := s.stored()
	err := s.add(s.resolve(pos), payload, r.maxSize)
	r.bytesBuffered += s.stored() - before
	return feedResult{
		buf:  append([]byte(nil), s.buf...),
		base: s.base,
		gap:  len(s.ooo) > 0,
		err:  err,
	}
}

// resolve returns the absolute offset of a segment. A segment without the
// stream's position metadata is taken as the next bytes in arrival order.
func (s *stream) resolve(pos position) int64 {
	switch {
	case s.mode == posOffset && pos.kind == posOffset:
		return pos.off
	case s.mode == posSeq && pos.kind == posSeq:
		end := s.end()
		return end + int64(seqDiff(s.seq0+uint32(end), pos.seq))
	default:
		return s.end()
	}
}

func (s *stream) add(off int64, data []byte, maxSize int) *StreamError {
	if len(data) == 0 {
		return nil
	}
	data, off, dup, err := s.dropHeld(off, data)
	if dup {
		s.retransmits++
	}
	if err != nil || len(data) == 0 {
		return err
	}
	if err := s.checkOOOOverlap(off, data); err != nil {
		return err
	}
	if off == s.end() {
		s.buf = append(s.buf, data...)
		s.absorbOOO()
	} else if err := s.insertOOO(off, data, maxSize); err != nil {
		return err
	}
	return s.bound(off, maxSize)
}

// dropHeld removes the bytes of data at off that the stream has already
// consumed or still holds contiguously, comparing the held ones. It reports
// whether any byte was a repeat.
func (s *stream) dropHeld(off int64, data []byte) ([]byte, int64, bool, *StreamError) {
	dup := false
	if off < s.base { // already consumed
		cut := min(s.base-off, int64(len(data)))
		data, off, dup = data[cut:], off+cut, true
	}
	if end := s.end(); off < end && len(data) > 0 {
		n := min(end-off, int64(len(data)))
		held := s.buf[off-s.base : off-s.base+n]
		if i := firstDiff(held, data[:n]); i >= 0 && s.strict {
			return nil, off, true, &StreamError{Kind: StreamOverlapConflict, Offset: off + int64(i)}
		}
		data, off, dup = data[n:], off+n, true
	}
	return data, off, dup, nil
}

// checkOOOOverlap compares data at off with every buffered out-of-order
// segment it overlaps.
func (s *stream) checkOOOOverlap(off int64, data []byte) *StreamError {
	if !s.strict {
		return nil
	}
	end := off + int64(len(data))
	for _, seg := range s.ooo {
		lo, hi := max(off, seg.off), min(end, seg.end())
		if lo >= hi {
			continue
		}
		if i := firstDiff(seg.data[lo-seg.off:hi-seg.off], data[lo-off:hi-off]); i >= 0 {
			return &StreamError{Kind: StreamOverlapConflict, Offset: lo + int64(i)}
		}
	}
	return nil
}

// absorbOOO moves out-of-order segments that the contiguous buffer now
// reaches into it.
func (s *stream) absorbOOO() {
	for len(s.ooo) > 0 && s.ooo[0].off <= s.end() {
		seg := s.ooo[0]
		s.ooo = s.ooo[1:]
		if tail := seg.end() - s.end(); tail > 0 {
			s.buf = append(s.buf, seg.data[int64(len(seg.data))-tail:]...)
		}
	}
	if len(s.ooo) == 0 {
		s.ooo = nil
	}
}

// insertOOO merges data at off (beyond the contiguous end) into the sorted
// set of disjoint, non-touching out-of-order segments. Overlaps were
// already compared.
func (s *stream) insertOOO(off int64, data []byte, maxSize int) *StreamError {
	end := off + int64(len(data))
	if s.strict && end-s.base > int64(maxSize) {
		return &StreamError{Kind: StreamOverflow, Offset: off}
	}
	merged := oooSegment{off: off, data: append([]byte(nil), data...)}
	out := make([]oooSegment, 0, len(s.ooo)+1)
	placed := false
	for _, seg := range s.ooo {
		switch {
		case seg.end() < merged.off:
			out = append(out, seg)
		case seg.off > merged.end():
			if !placed {
				out = append(out, merged)
				placed = true
			}
			out = append(out, seg)
		default: // overlapping or touching: union
			merged = unionSegments(merged, seg)
		}
	}
	if !placed {
		out = append(out, merged)
	}
	if len(out) > maxOOOSegments {
		if s.strict {
			return &StreamError{Kind: StreamOutOfOrderLimit, Offset: off}
		}
		return nil // lenient: drop the segment, keep the bounded set
	}
	s.ooo = out
	return nil
}

// unionSegments joins new data a with held segment b.
func unionSegments(a, b oooSegment) oooSegment {
	lo, hi := min(a.off, b.off), max(a.end(), b.end())
	data := make([]byte, hi-lo)
	copy(data[a.off-lo:], a.data)
	copy(data[b.off-lo:], b.data) // held bytes win where a lenient stream conflicts
	return oooSegment{off: lo, data: data}
}

// bound enforces the per-stream byte limit: an error for strict streams,
// a sliding window over the contiguous buffer otherwise.
func (s *stream) bound(off int64, maxSize int) *StreamError {
	if s.strict {
		if s.stored() > maxSize {
			return &StreamError{Kind: StreamOverflow, Offset: off}
		}
		return nil
	}
	if excess := len(s.buf) - maxSize; excess > 0 {
		s.buf = append([]byte(nil), s.buf[excess:]...)
		s.base += int64(excess)
		s.absorbOOO()
	}
	return nil
}

// firstDiff returns the index of the first differing byte, or -1.
func firstDiff(a, b []byte) int {
	if bytes.Equal(a, b) {
		return -1
	}
	for i := range a {
		if a[i] != b[i] {
			return i
		}
	}
	return -1
}

// trim consumes the first n bytes of the stream if its watermark is still
// base (the view that was parsed).
func (r *reassembler) trim(key string, base int64, n int) {
	r.mu.Lock()
	defer r.mu.Unlock()
	s, ok := r.streams[key]
	if !ok || s.base != base || n <= 0 {
		return
	}
	n = min(n, len(s.buf))
	s.buf = s.buf[n:]
	s.base += int64(n)
	r.bytesBuffered -= n
}

// fail discards a session stream's bytes and marks it failed until
// complete; later feeds return err.
func (r *reassembler) fail(key string, err error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if s, ok := r.streams[key]; ok {
		r.bytesBuffered -= s.stored()
		s.buf, s.ooo = nil, nil
		s.failed = err
	}
}

// failure returns the error a session stream failed with, or nil.
func (r *reassembler) failure(key string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if s, ok := r.streams[key]; ok {
		return s.failed
	}
	return nil
}

// complete removes a stream; the next segment starts a new one.
func (r *reassembler) complete(key string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if s, ok := r.streams[key]; ok {
		r.bytesBuffered -= s.stored()
		delete(r.streams, key)
		r.activeStreams--
	}
}

// sweep removes streams idle longer than idleTimeout, except session
// streams, whose lifetime the caller owns (EndStream). It runs at most once
// per idleTimeout.
func (r *reassembler) sweep(now time.Time) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if now.Sub(r.lastSweep) < r.idleTimeout {
		return
	}
	r.lastSweep = now
	for key, s := range r.streams {
		if !s.keep && now.Sub(s.lastUpdate) > r.idleTimeout {
			r.bytesBuffered -= s.stored()
			delete(r.streams, key)
			r.activeStreams--
		}
	}
}

// retransmissions returns the duplicate-segment count of a stream.
func (r *reassembler) retransmissions(key string) uint64 {
	r.mu.Lock()
	defer r.mu.Unlock()
	if s, ok := r.streams[key]; ok {
		return s.retransmits
	}
	return 0
}

// stats returns the live stream count and the bytes held.
func (r *reassembler) stats() (streams, bytes int) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.activeStreams, r.bytesBuffered
}
