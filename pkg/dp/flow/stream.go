// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

package flow

import (
	"bytes"
	"errors"
)

// Stream errors.
var (
	// ErrOverlapConflict reports a segment whose bytes differ from bytes of
	// the same offsets received before.
	ErrOverlapConflict = errors.New("flow: overlapping bytes differ from bytes already received")
	// ErrStreamBound reports that buffered history and out-of-order bytes
	// would exceed the stream's bounds.
	ErrStreamBound = errors.New("flow: stream buffer bound exceeded")
	// ErrBeforeStream reports a segment that starts before the first byte
	// after the SYN.
	ErrBeforeStream = errors.New("flow: segment before the stream start")
)

// SeqSpace maps one direction's 32-bit TCP sequence numbers to absolute
// offsets. Offset 0 is the first byte after the SYN (ISN+1); offsets never
// wrap. Each sequence number is unwrapped to the offset nearest the highest
// offset seen so far, so a stream may cross 2^32 any number of times.
type SeqSpace struct {
	isn    uint32
	refSeq uint32
	refOff int64
}

// NewSeqSpace returns the sequence space of a direction whose SYN carried isn.
func NewSeqSpace(isn uint32) SeqSpace {
	return SeqSpace{isn: isn, refSeq: isn + 1}
}

// Offset returns the absolute offset of seq. It is negative for sequence
// numbers before the first byte after the SYN.
func (s *SeqSpace) Offset(seq uint32) int64 {
	return s.refOff + int64(int32(seq-s.refSeq))
}

// Seq returns the wire sequence number of an absolute offset.
func (s *SeqSpace) Seq(off int64) uint32 {
	return s.isn + 1 + uint32(off) // #nosec G115 -- sequence numbers are offsets mod 2^32
}

// Advance moves the unwrapping reference to off when it is beyond the
// highest offset seen.
func (s *SeqSpace) Advance(off int64) {
	if off > s.refOff {
		s.refOff = off
		s.refSeq = s.Seq(off)
	}
}

// ByteStream keeps one direction's received bytes for in-order delivery and
// byte-identity checks. Every byte is delivered once, in order. Bytes that
// arrive again are compared with what was received; history is kept until
// the receiver acknowledges it, and bytes below that point are duplicates
// the receiver already holds, so they are not compared.
type ByteStream struct {
	next     int64 // every byte below next was delivered
	histBase int64
	hist     []byte  // bytes [histBase, next)
	ooo      []chunk // bytes beyond next, sorted, non-overlapping
	oooBytes int
	maxBytes int
	maxSegs  int
}

type chunk struct {
	off  int64
	data []byte
}

func (c chunk) end() int64 { return c.off + int64(len(c.data)) }

// NewByteStream returns a stream that holds at most maxBytes of history and
// out-of-order data, in at most maxSegs out-of-order pieces.
func NewByteStream(maxBytes, maxSegs int) *ByteStream {
	return &ByteStream{maxBytes: maxBytes, maxSegs: maxSegs}
}

// Next returns the offset of the first byte not yet delivered.
func (b *ByteStream) Next() int64 { return b.next }

// Buffered returns the bytes held as history and out-of-order data.
func (b *ByteStream) Buffered() int { return len(b.hist) + b.oooBytes }

// Add records data received at off. It returns the bytes that became
// deliverable in order, starting at offset start (fresh is empty when
// nothing new is contiguous). On error the stream is unchanged.
func (b *ByteStream) Add(off int64, data []byte) (start int64, fresh []byte, err error) {
	if off < 0 {
		return b.next, nil, ErrBeforeStream
	}
	end := off + int64(len(data))
	if err := b.compare(off, data); err != nil {
		return b.next, nil, err
	}
	if end <= b.next {
		return b.next, nil, nil
	}
	if off > b.next {
		return b.next, nil, b.addOutOfOrder(off, data)
	}
	if len(b.hist)+b.oooBytes+int(end-b.next) > b.maxBytes {
		return b.next, nil, ErrStreamBound
	}
	start = b.next
	b.hist = append(b.hist, data[b.next-off:]...)
	b.next = end
	b.drainOutOfOrder()
	return start, append([]byte(nil), b.hist[start-b.histBase:]...), nil
}

// Ack drops history below off: the receiver acknowledged those bytes.
func (b *ByteStream) Ack(off int64) {
	off = min(off, b.next)
	if off <= b.histBase {
		return
	}
	b.hist = append([]byte(nil), b.hist[off-b.histBase:]...)
	b.histBase = off
}

// compare checks data against history and out-of-order pieces.
func (b *ByteStream) compare(off int64, data []byte) error {
	end := off + int64(len(data))
	if lo, hi := max(off, b.histBase), min(end, b.next); lo < hi {
		if !bytes.Equal(data[lo-off:hi-off], b.hist[lo-b.histBase:hi-b.histBase]) {
			return ErrOverlapConflict
		}
	}
	for _, c := range b.ooo {
		if lo, hi := max(off, c.off), min(end, c.end()); lo < hi {
			if !bytes.Equal(data[lo-off:hi-off], c.data[lo-c.off:hi-c.off]) {
				return ErrOverlapConflict
			}
		}
	}
	return nil
}

// addOutOfOrder stores the parts of data that no out-of-order piece covers.
func (b *ByteStream) addOutOfOrder(off int64, data []byte) error {
	end := off + int64(len(data))
	var pieces []chunk
	cur := off
	for _, c := range b.ooo {
		if c.end() <= cur || c.off >= end {
			continue
		}
		if c.off > cur {
			pieces = append(pieces, chunk{off: cur, data: data[cur-off : c.off-off]})
		}
		cur = max(cur, c.end())
	}
	if cur < end {
		pieces = append(pieces, chunk{off: cur, data: data[cur-off:]})
	}
	added := 0
	for _, p := range pieces {
		added += len(p.data)
	}
	if len(b.hist)+b.oooBytes+added > b.maxBytes || len(b.ooo)+len(pieces) > b.maxSegs {
		return ErrStreamBound
	}
	for _, p := range pieces {
		b.insert(chunk{off: p.off, data: append([]byte(nil), p.data...)})
	}
	b.oooBytes += added
	return nil
}

func (b *ByteStream) insert(c chunk) {
	i := 0
	for i < len(b.ooo) && b.ooo[i].off < c.off {
		i++
	}
	b.ooo = append(b.ooo, chunk{})
	copy(b.ooo[i+1:], b.ooo[i:])
	b.ooo[i] = c
}

// drainOutOfOrder moves pieces that became contiguous into history.
func (b *ByteStream) drainOutOfOrder() {
	for len(b.ooo) > 0 && b.ooo[0].off <= b.next {
		c := b.ooo[0]
		b.ooo = b.ooo[1:]
		b.oooBytes -= len(c.data)
		if c.end() > b.next {
			b.hist = append(b.hist, c.data[b.next-c.off:]...)
			b.next = c.end()
		}
	}
}
