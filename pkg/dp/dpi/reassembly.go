// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

package dpi

import (
	"bytes"
	"errors"
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
	strict  bool
	mode    posKind
	seq0    uint32 // posSeq: sequence number of offset 0
	synSeen bool
	synSeq  uint32 // payload sequence following the SYN, for late capture copies
	keep    bool   // session stream: lifetime owned by the caller, never idle-swept
	// verify keeps consumed bytes in hist so that a retransmission of them
	// is compared too; it follows the latest segment's request.
	verify bool

	base       int64  // absolute offset of buf[0]; the consumed watermark
	buf        []byte // contiguous bytes from base
	hist       []byte // verify: the last consumed bytes, [base-len(hist), base)
	ooo        []oooSegment
	lastUpdate time.Time

	retransmits uint64 // segments that repeated bytes already held or consumed
	failed      error  // session stream failure, until the caller ends it

	// closed marks a fail-closed stream that an in-window FIN or RST ended.
	// It holds no bytes; closeNext is the sequence number a later RST of
	// this direction carries in window.
	closed    bool
	closeNext uint32
	// lost marks a fail-closed stream whose partial frame the idle sweep
	// dropped: its next bytes cannot be framed, as for a stream that began
	// without a SYN.
	lost bool
}

// pickedUp reports a stream whose bytes need not start at a frame: it
// began without an observed SYN, or the idle sweep dropped its partial
// frame.
func (s *stream) pickedUp() bool { return !s.synSeen || s.lost }

// midStream reports a stream that failed as picked up mid-connection.
func midStream(err error) bool {
	var se *StreamError
	return errors.As(err, &se) && se.Kind == StreamMidStream
}

func (s *stream) end() int64 { return s.base + int64(len(s.buf)) }

func (s *stream) stored() int {
	n := len(s.buf)
	for _, seg := range s.ooo {
		n += len(seg.data)
	}
	return n
}

// held is every byte the stream keeps: stored bytes and consumed history.
func (s *stream) held() int { return s.stored() + len(s.hist) }

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

// open anchors a legacy stream at a handshake. A late second capture of the
// same SYN must not reset bytes already parsed on the first interface.
//
// A SYN with a new sequence number re-anchors the stream unless the stream
// fails closed: a live fail-closed stream (one that no in-window FIN or RST
// ended) does not resynchronize, and open returns its StreamResync error
// for the caller to fail it. A failed fail-closed stream stays failed,
// except one that began without a SYN and failed as picked up
// mid-connection: a SYN starts the client's next connection on the tuple.
// A stream that lost its partial frame was live, so it stays failed.
//
// A fail-closed SYN starts a stream, a new one or the next connection of a
// failed or closed one, only when it belongs to a handshake the kernel's
// connection tracking has not seen complete (handshake). Any other was
// sent into an established connection, which a stream picked up
// mid-connection, or none, may belong to: anchoring at it would let its
// sender choose where framing starts.
func (r *reassembler) open(key string, seq uint32, now time.Time, failClosed, handshake bool) *StreamError {
	r.mu.Lock()
	defer r.mu.Unlock()
	s, ok := r.streams[key]
	switch {
	case !ok:
		if failClosed && !handshake {
			return nil
		}
	case failClosed && s.failed != nil:
		if !midStream(s.failed) || s.synSeen || !handshake {
			return nil
		}
	case s.synSeen && s.synSeq == seq && !s.closed:
		s.lastUpdate = now
		return nil
	case failClosed && !s.closed:
		return &StreamError{Kind: StreamResync, Offset: s.end()}
	case failClosed && !handshake:
		return nil
	}
	if ok {
		r.bytesBuffered -= s.held()
	} else {
		r.activeStreams++
	}
	r.streams[key] = &stream{strict: true, mode: posSeq, seq0: seq, synSeen: true, synSeq: seq, verify: failClosed, lastUpdate: now}
	return nil
}

// feed adds one segment. A new stream starts at offset 0 in the given
// position mode; strict and keep are fixed at creation.
//
// A segment that asks to verify (it fails closed) is not taken by a stream
// picked up mid-connection (pickedUp), which returns a StreamMidStream
// error, nor by a closed stream, whose receiver delivers no bytes after
// the close. Other segments start a new stream in a closed or lost
// stream's direction.
//
// Bytes the stream still holds are compared byte for byte; a difference is
// a conflict. Bytes below the consumed watermark are duplicates; with
// verify set on a strict stream they are compared with the consumed
// history as well, and a consumed byte older than the history cannot be
// verified. verify applies from this segment on; turning it off drops the
// history.
func (r *reassembler) feed(key string, pos position, payload []byte, now time.Time, strict, keep, verify bool) feedResult {
	r.mu.Lock()
	defer r.mu.Unlock()

	s, ok := r.streams[key]
	if ok && s.closed && strict && verify {
		s.lastUpdate = now
		return feedResult{base: s.base}
	}
	if !ok || s.closed || s.lost && !verify { // neither holds bytes
		if !ok {
			r.activeStreams++
		}
		s = &stream{strict: strict, mode: pos.kind, seq0: pos.seq, keep: keep}
		r.streams[key] = s
	}
	if s.failed != nil {
		return feedResult{failed: s.failed}
	}
	s.lastUpdate = now
	if strict && verify && !keep && s.pickedUp() {
		return feedResult{base: s.base, err: &StreamError{Kind: StreamMidStream, Offset: s.end()}}
	}
	before := s.held()
	s.verify = strict && verify
	if !s.verify {
		s.hist = nil
	}
	err := s.add(s.resolve(pos), payload, r.maxSize)
	r.bytesBuffered += s.held() - before
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
// consumed or still holds contiguously, comparing the held ones (and, with
// verify, the consumed ones). It reports whether any byte was a repeat.
func (s *stream) dropHeld(off int64, data []byte) ([]byte, int64, bool, *StreamError) {
	dup := false
	if off < s.base { // already consumed
		cut := min(s.base-off, int64(len(data)))
		if err := s.verifyConsumed(off, data[:cut]); err != nil {
			return nil, off, true, err
		}
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

// verifyConsumed compares consumed bytes at off with the history of a
// verify stream. Other streams do not compare consumed bytes.
func (s *stream) verifyConsumed(off int64, data []byte) *StreamError {
	if !s.verify {
		return nil
	}
	histBase := s.base - int64(len(s.hist))
	if off < histBase {
		return &StreamError{Kind: StreamUnverifiedRetransmission, Offset: off}
	}
	held := s.hist[off-histBase : off-histBase+int64(len(data))]
	if i := firstDiff(held, data); i >= 0 {
		return &StreamError{Kind: StreamOverlapConflict, Offset: off + int64(i)}
	}
	return nil
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
// base (the view that was parsed). A verify stream moves them into its
// history, which keeps the last maxSize consumed bytes.
func (r *reassembler) trim(key string, base int64, n int) {
	r.mu.Lock()
	defer r.mu.Unlock()
	s, ok := r.streams[key]
	if !ok || s.base != base || n <= 0 {
		return
	}
	before := s.held()
	n = min(n, len(s.buf))
	if s.verify {
		s.hist = append(s.hist, s.buf[:n]...)
		if excess := len(s.hist) - r.maxSize; excess > 0 {
			s.hist = s.hist[excess:]
		}
	}
	s.buf = s.buf[n:]
	s.base += int64(n)
	r.bytesBuffered += s.held() - before
}

// fail discards a stream's bytes and marks it failed until complete,
// creating the stream when there is none; later feeds return err. A failed
// stream keeps its first error.
func (r *reassembler) fail(key string, err error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	s, ok := r.streams[key]
	if !ok {
		s = &stream{strict: true}
		r.streams[key] = s
		r.activeStreams++
	}
	if s.failed != nil {
		return
	}
	r.bytesBuffered -= s.held()
	s.buf, s.ooo, s.hist = nil, nil, nil
	s.closed, s.lost = false, false
	s.failed = err
}

// watermark returns a stream's consumed watermark, 0 without a stream.
func (r *reassembler) watermark(key string) int64 {
	r.mu.Lock()
	defer r.mu.Unlock()
	if s, ok := r.streams[key]; ok {
		return s.base
	}
	return 0
}

// failure returns the error a stream failed with, or nil.
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
	r.completeLocked(key)
}

func (r *reassembler) completeLocked(key string) {
	if s, ok := r.streams[key]; ok {
		r.bytesBuffered -= s.held()
		delete(r.streams, key)
		r.activeStreams--
	}
}

// sweep removes streams idle longer than idleTimeout, except session
// streams, whose lifetime the caller owns (EndStream), failed streams,
// which hold no bytes and stay failed until their flow ends, and live
// fail-closed streams, which keep their position until their flow ends:
// one holding a partial frame drops it and is lost, another drops only its
// consumed history. It runs at most once per idleTimeout.
func (r *reassembler) sweep(now time.Time) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if now.Sub(r.lastSweep) < r.idleTimeout {
		return
	}
	r.lastSweep = now
	for key, s := range r.streams {
		if s.keep || s.failed != nil || now.Sub(s.lastUpdate) <= r.idleTimeout {
			continue
		}
		r.bytesBuffered -= s.held()
		switch {
		case !s.verify || s.closed:
			delete(r.streams, key)
			r.activeStreams--
		case s.stored() > 0:
			s.base = s.end() // the position after the dropped bytes
			s.buf, s.ooo, s.hist = nil, nil, nil
			s.lost = true
		default:
			s.hist = nil
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
