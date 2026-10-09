// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

package flow

import (
	"errors"
	"testing"
)

func TestSeqSpaceOffsetsAndWrap(t *testing.T) {
	s := NewSeqSpace(0xfffffff0)
	if got := s.Offset(0xfffffff1); got != 0 {
		t.Fatalf("first byte offset = %d", got)
	}
	if got := s.Offset(0xfffffff0); got != -1 {
		t.Fatalf("SYN offset = %d, want -1", got)
	}
	// Crossing 2^32: seq 0x10 is 31 bytes after the first byte.
	if got := s.Offset(0x10); got != 0x1f {
		t.Fatalf("wrapped offset = %d", got)
	}
	s.Advance(0x1f)
	if got := s.Seq(0x1f); got != 0x10 {
		t.Fatalf("Seq = %#x", got)
	}
	// Many epochs: advance in 1 GiB steps across several wraps.
	var off int64
	for i := 0; i < 10; i++ {
		off += 1 << 30
		seq := s.Seq(off)
		if got := s.Offset(seq); got != off {
			t.Fatalf("epoch %d: Offset(Seq(%d)) = %d", i, off, got)
		}
		s.Advance(off)
	}
	if s.Offset(s.Seq(off)-5) != off-5 {
		t.Fatal("retransmission below the reference must stay below it")
	}
}

func TestByteStreamInOrderOutOfOrderAndRetransmit(t *testing.T) {
	b := NewByteStream(64, 4)
	start, fresh, err := b.Add(0, []byte("abcd"))
	if err != nil || start != 0 || string(fresh) != "abcd" {
		t.Fatalf("first add = %d %q %v", start, fresh, err)
	}
	if _, fresh, err = b.Add(8, []byte("ijkl")); err != nil || len(fresh) != 0 {
		t.Fatalf("out-of-order add = %q %v", fresh, err)
	}
	if _, _, err = b.Add(8, []byte("ijkX")); !errors.Is(err, ErrOverlapConflict) {
		t.Fatalf("conflicting out-of-order = %v", err)
	}
	start, fresh, err = b.Add(2, []byte("cdefgh"))
	if err != nil || start != 4 || string(fresh) != "efghijkl" {
		t.Fatalf("gap fill = %d %q %v", start, fresh, err)
	}
	if _, fresh, err = b.Add(0, []byte("abcd")); err != nil || len(fresh) != 0 {
		t.Fatalf("retransmit = %q %v", fresh, err)
	}
	if _, _, err = b.Add(1, []byte("bX")); !errors.Is(err, ErrOverlapConflict) {
		t.Fatalf("conflicting retransmit = %v", err)
	}
	b.Ack(6)
	// Below the acknowledged point bytes are duplicates the receiver has.
	if _, fresh, err = b.Add(0, []byte("ZZZZ")); err != nil || len(fresh) != 0 {
		t.Fatalf("acknowledged duplicate = %q %v", fresh, err)
	}
	if _, _, err = b.Add(5, []byte("zX")); !errors.Is(err, ErrOverlapConflict) {
		t.Fatalf("partly acknowledged conflict = %v", err)
	}
	if b.Next() != 12 || b.Buffered() != 6 {
		t.Fatalf("next=%d buffered=%d", b.Next(), b.Buffered())
	}
	if _, _, err = b.Add(-1, []byte("x")); !errors.Is(err, ErrBeforeStream) {
		t.Fatalf("before stream = %v", err)
	}
}

func TestByteStreamBounds(t *testing.T) {
	b := NewByteStream(8, 2)
	if _, _, err := b.Add(0, []byte("12345678")); err != nil {
		t.Fatal(err)
	}
	if _, _, err := b.Add(8, []byte("9")); !errors.Is(err, ErrStreamBound) {
		t.Fatalf("byte bound = %v", err)
	}
	b.Ack(8)
	if _, _, err := b.Add(10, []byte("a")); err != nil {
		t.Fatal(err)
	}
	if _, _, err := b.Add(12, []byte("b")); err != nil {
		t.Fatal(err)
	}
	if _, _, err := b.Add(14, []byte("c")); !errors.Is(err, ErrStreamBound) {
		t.Fatalf("segment bound = %v", err)
	}
	// An overlapping out-of-order piece stores only the uncovered bytes.
	if _, _, err := b.Add(10, []byte("a")); err != nil || b.Buffered() != 2 {
		t.Fatalf("duplicate out-of-order: buffered=%d err=%v", b.Buffered(), err)
	}
	start, fresh, err := b.Add(8, []byte("xyazb"))
	if err != nil || start != 8 || string(fresh) != "xyazb" {
		t.Fatalf("fill = %d %q %v", start, fresh, err)
	}
}
