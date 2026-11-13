// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

package dpi

import (
	"bytes"
	"errors"
	"sync"
	"time"

	"github.com/tonylturner/containd/pkg/dp/flow"
	"github.com/tonylturner/containd/pkg/dp/limits"
)

const (
	// maxOOOSegments bounds the holes a stream may buffer beyond. It is at
	// least the IEC104 holdback bound of 32 held packets per session, so
	// the reassembler never fails before the engine's own bound.
	maxOOOSegments = 32
	// Each index slot is an int64 offset plus a slice descriptor. The
	// embedded backing array is reserved in addition to stream metadata.
	oooIndexBytes = maxOOOSegments * 32
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
	memory                *flow.InspectionMemory
	resources             limits.Resources
	enforcing             bool
	bufCharge, histCharge int
	segments              [maxOOOSegments]oooSegment
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
	// lost marks a fail-closed stream that dropped its bytes: the idle
	// sweep dropped its partial frame, or a handshake SYN began a new
	// connection on its tuple. Its next bytes cannot be framed, as for a
	// stream that began without a SYN.
	lost bool
}

// pickedUp reports a stream whose bytes need not start at a frame: it
// began without an observed SYN, or it is lost.
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
	buf            []byte // copy of the contiguous bytes from base
	base           int64
	gap            bool // bytes are buffered beyond a hole
	err            *StreamError
	failed         error // the stream failed earlier; nothing was fed
	packetStart    int
	hasPacketStart bool
	enforcing      bool // allocation class captured at stream admission
}

// reassembler collects TCP payloads per stream direction so that decoders
// can inspect data that spans segments.
type reassembler struct {
	mu          sync.Mutex
	streams     map[string]*stream
	maxSize     int
	idleTimeout time.Duration
	lastSweep   time.Time
	resources   limits.Resources

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
	maxStreamSize = min(maxStreamSize, defaultReassemblyMax)
	return &reassembler{
		streams:     make(map[string]*stream),
		maxSize:     maxStreamSize,
		idleTimeout: idleTimeout,
		resources:   limits.NewResources(nil, nil),
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
// A fail-closed SYN starts a stream, a new one or the next connection of a
// closed one, only when it belongs to a handshake the kernel's connection
// tracking has not seen complete (handshake). Any other was sent into an
// established connection, which a stream picked up mid-connection, or none,
// may belong to: anchoring at it would let its sender choose where framing
// starts. A failed fail-closed stream stays failed, except one that failed
// as picked up mid-connection: the engine closes that connection, so a
// handshake SYN starts the client's next one on the tuple.
// A non-admitting stream also restarts at a kernel-tracked handshake with
// a different ISN, even when its owner has not retired its state already.
// Replaying its original SYN must not clear the denial.
//
// A SYN with a new sequence number on a live fail-closed stream (one that
// no in-window FIN or RST ended) carries no payload and anchors nothing.
// Without the handshake mark, connection tracking still holds the
// connection established and the stream keeps its position: the server
// answers such a SYN with a challenge ACK, and the RST a reconnecting
// client sends in reply ends the stream in window (CloseStream). With the
// mark, connection tracking starts a new connection that the stream cannot
// follow: the stream drops its bytes and is lost, so its next bytes are a
// mid-stream pickup.
//
// open reports whether the stream is anchored at this SYN and whether it
// discarded the prior stream's accumulated state.
func (r *reassembler) open(key string, seq uint32, now time.Time, failClosed, handshake bool) (anchored, discarded bool, err *StreamError) {
	r.mu.Lock()
	defer r.mu.Unlock()
	s, ok := r.streams[key]
	if ok && stateLimit(s.failed) {
		return false, false, nil
	}
	switch {
	case !ok:
		if failClosed && !handshake {
			return false, false, nil
		}
	case failClosed && s.failed != nil:
		var se *StreamError
		nonAdmit := errors.As(s.failed, &se) && se.Kind == StreamNonAdmit && s.synSeen && s.synSeq != seq
		if !handshake || !midStream(s.failed) && !nonAdmit {
			return false, false, nil
		}
	case s.synSeen && s.synSeq == seq && !s.closed:
		s.lastUpdate = now
		return true, false, nil
	case failClosed && !s.closed:
		if handshake {
			r.loseLocked(s)
			discarded = true
		}
		s.lastUpdate = now
		return false, discarded, nil
	case failClosed && !handshake:
		return false, false, nil
	}
	if ok {
		r.completeLocked(key)
	}
	s, err = r.allocate(key, failClosed)
	if err != nil {
		return false, ok, err
	}
	s.strict, s.mode, s.seq0, s.synSeen, s.synSeq, s.verify, s.lastUpdate = true, posSeq, seq, true, seq, failClosed, now
	r.streams[key] = s
	r.activeStreams++
	return true, ok, nil
}

// loseLocked drops the bytes of a live fail-closed stream, which keeps its
// position: its next bytes need not start a frame (lost).
func (r *reassembler) loseLocked(s *stream) {
	r.bytesBuffered -= s.held()
	s.base = s.end() // the position after the dropped bytes
	s.clearBytes()
	s.lost = true
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
		if ok {
			r.completeLocked(key)
		}
		var err *StreamError
		s, err = r.allocate(key, verify)
		if err != nil {
			return feedResult{err: err}
		}
		r.activeStreams++
		s.strict, s.mode, s.seq0, s.keep = strict, pos.kind, pos.seq, keep
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
		s.memory.Refund(s.histCharge)
		s.histCharge = 0
	}
	off := s.resolve(pos)
	inOrder := pos.kind != posAppend && s.mode == pos.kind && off == s.end() && len(payload) > 0
	err := s.add(off, payload, r.maxSize)
	r.bytesBuffered += s.held() - before
	return feedResult{
		buf:            append([]byte(nil), s.buf...),
		base:           s.base,
		gap:            len(s.ooo) > 0,
		err:            err,
		packetStart:    int(off - s.base),
		hasPacketStart: inOrder && err == nil && off >= s.base && off+int64(len(payload)) <= s.end(),
		enforcing:      s.enforcing,
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
		if s.strict {
			next, absorbed := s.end()+int64(len(data)), 0
			for absorbed < len(s.ooo) && s.ooo[absorbed].off <= next {
				next = max(next, s.ooo[absorbed].end())
				absorbed++
			}
			total := int(next - s.base)
			for _, seg := range s.ooo[absorbed:] {
				total += len(seg.data)
			}
			if total > maxSize {
				return &StreamError{Kind: StreamOverflow, Offset: off}
			}
		}
		// Lenient streams retain only a fixed-size window, even if a caller
		// supplies a segment larger than the normal capture buffer.
		if !s.strict && len(data) > maxSize {
			s.base += int64(len(s.buf) + len(data) - maxSize)
			s.buf = nil
			s.memory.Refund(s.bufCharge)
			s.bufCharge = 0
			data = data[len(data)-maxSize:]
		}
		if err := s.appendBuffer(data); err != nil {
			return err
		}
		if err := s.absorbOOO(); err != nil {
			return err
		}
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
func (s *stream) absorbOOO() *StreamError {
	for len(s.ooo) > 0 && s.ooo[0].off <= s.end() {
		seg := s.ooo[0]
		if tail := seg.end() - s.end(); tail > 0 {
			if err := s.appendBuffer(seg.data[int64(len(seg.data))-tail:]); err != nil {
				return err
			}
		}
		old := cap(seg.data)
		copy(s.ooo, s.ooo[1:])
		s.ooo[len(s.ooo)-1] = oooSegment{}
		s.ooo = s.ooo[:len(s.ooo)-1]
		s.memory.Refund(old)
	}
	return nil
}

// insertOOO merges data at off (beyond the contiguous end) into the sorted
// set of disjoint, non-touching out-of-order segments. Overlaps were
// already compared.
func (s *stream) insertOOO(off int64, data []byte, maxSize int) *StreamError {
	end := off + int64(len(data))
	if s.strict && end-s.base > int64(maxSize) {
		return &StreamError{Kind: StreamOverflow, Offset: off}
	}
	first := 0
	for first < len(s.ooo) && s.ooo[first].end() < off {
		first++
	}
	last := first
	lo, hi := off, end
	for last < len(s.ooo) && s.ooo[last].off <= hi {
		lo, hi = min(lo, s.ooo[last].off), max(hi, s.ooo[last].end())
		last++
	}
	if len(s.ooo)-(last-first)+1 > maxOOOSegments {
		if s.strict {
			return &StreamError{Kind: StreamOutOfOrderLimit, Offset: off}
		}
		return nil // lenient: drop the segment, keep the bounded set
	}
	if hi-lo > int64(defaultReassemblyMax) {
		return &StreamError{Kind: StreamOverflow, Offset: off}
	}
	if !s.memory.Reserve(int(hi - lo)) {
		return s.allocationFailure()
	}
	merged := make([]byte, int(hi-lo))
	copy(merged[off-lo:], data)
	old := 0
	for _, seg := range s.ooo[first:last] {
		copy(merged[seg.off-lo:], seg.data)
		old += cap(seg.data)
	}
	count := len(s.ooo)
	if last == first {
		s.ooo = s.ooo[:count+1]
	}
	copy(s.ooo[first+1:], s.ooo[last:count])
	newCount := count - (last - first) + 1
	clear(s.ooo[newCount:])
	s.ooo = s.ooo[:newCount]
	s.ooo[first] = oooSegment{off: lo, data: merged}
	s.memory.Refund(old)
	return nil
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
		s.buf = s.buf[excess:]
		s.base += int64(excess)
		return s.absorbOOO()
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
func (r *reassembler) trim(key string, base int64, n int) *StreamError {
	r.mu.Lock()
	defer r.mu.Unlock()
	s, ok := r.streams[key]
	if !ok || s.base != base || n <= 0 {
		return nil
	}
	before := s.held()
	n = min(n, len(s.buf))
	if s.verify {
		if err := s.replaceHistory(n, r.maxSize); err != nil {
			return err
		}
	}
	s.buf = s.buf[n:]
	s.base += int64(n)
	r.bytesBuffered += s.held() - before
	return nil
}

// resync abandons held passive bytes through the highest observed position,
// without forgetting sequence space or decoder lifetime. Strict decoders never
// use this path. The next in-order payload can supply a new packet anchor.
func (r *reassembler) resync(key string, pos position, size int) {
	r.mu.Lock()
	defer r.mu.Unlock()
	s := r.streams[key]
	if s == nil {
		return
	}
	next := s.end()
	if pos.kind != posAppend {
		next = max(next, s.resolve(pos)+int64(size))
	}
	for _, seg := range s.ooo {
		next = max(next, seg.end())
	}
	r.bytesBuffered -= s.held()
	s.clearBytes()
	s.base = next
}

// fail discards a stream's bytes and marks it failed until complete,
// never creating an unadmitted stream; later feeds return err. A failed
// stream keeps its first error.
func (r *reassembler) fail(key string, err error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	s, ok := r.streams[key]
	if !ok {
		return
	}
	if s.failed != nil {
		err = s.failed
	}
	r.bytesBuffered -= s.held()
	s.clearBytes()
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
		s.clearBytes()
		s.memory.Release()
	}
}

// sweep expires decoder state for streams idle longer than idleTimeout,
// except session streams, whose lifetime the caller owns (EndStream), and
// failed streams, which stay failed until their flow ends. Live fail-closed
// streams keep their position: one holding a partial frame drops it and is
// lost, while another drops only its consumed history. It returns keys
// whose decoder state was discarded; a fail-closed stream may remain to
// preserve its transport position. It runs at most once per idleTimeout.
func (r *reassembler) sweep(now time.Time) []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	if now.Sub(r.lastSweep) < r.idleTimeout {
		return nil
	}
	r.lastSweep = now
	var expired []string
	for key, s := range r.streams {
		if s.keep || s.failed != nil || now.Sub(s.lastUpdate) <= r.idleTimeout {
			continue
		}
		switch {
		case !s.verify || s.closed:
			r.completeLocked(key)
			expired = append(expired, key)
		case s.stored() > 0:
			r.loseLocked(s)
			expired = append(expired, key)
		default:
			r.bytesBuffered -= len(s.hist)
			s.hist = nil
			s.memory.Refund(s.histCharge)
			s.histCharge = 0
			expired = append(expired, key)
		}
	}
	return expired
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
