// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

package dpi

import (
	"testing"
	"time"
)

func FuzzReassemblerFeed(f *testing.F) {
	f.Add([]byte{0x01, 0x02}, uint32(100), []byte{0x03, 0x04}, uint32(102), uint16(4096), uint8(0))
	f.Add([]byte{0x01, 0x02}, uint32(100), []byte{0x05, 0x06}, uint32(105), uint16(8), uint8(2))
	f.Add([]byte{}, uint32(0), []byte{}, uint32(0), uint16(1), uint8(0))

	f.Fuzz(func(t *testing.T, seg1 []byte, seq1 uint32, seg2 []byte, seq2 uint32, maxSize uint16, trim uint8) {
		if maxSize == 0 {
			maxSize = 1
		}
		if len(seg1) > 1024 {
			seg1 = seg1[:1024]
		}
		if len(seg2) > 1024 {
			seg2 = seg2[:1024]
		}

		r := NewReassembler(int(maxSize), time.Second)
		now := time.Unix(1, 0).UTC()

		_ = r.Feed("flow1", seg1, now, seq1)
		_ = r.Feed("flow1", seg2, now.Add(time.Millisecond), seq2)
		r.Trim("flow1", int(trim))
		r.Sweep(now.Add(2 * time.Second))
		_ = r.Feed("flow1", seg1, now.Add(3*time.Second), seq1)
		r.Complete("flow1")

		if r.ActiveStreams < 0 {
			t.Fatalf("active streams should never be negative: %d", r.ActiveStreams)
		}
		if r.BytesBuffered < 0 {
			t.Fatalf("bytes buffered should never be negative: %d", r.BytesBuffered)
		}
		if sb, ok := r.streams["flow1"]; ok && len(sb.buf) > int(maxSize) {
			t.Fatalf("stream buffer exceeded max size: %d > %d", len(sb.buf), maxSize)
		}
	})
}
