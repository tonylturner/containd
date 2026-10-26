// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

package dpi

import (
	"testing"
	"time"
)

func BenchmarkReassemblerFeedInOrder(b *testing.B) {
	r := newReassembler(64*1024, time.Minute)
	now := time.Unix(1, 0).UTC()
	payload := []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06}

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		seq := uint32(100 + (i * len(payload)))
		res := r.feed("bench-in-order", position{kind: posSeq, seq: seq}, payload, now, true, false)
		r.trim("bench-in-order", res.base, len(res.buf))
	}
}

func BenchmarkReassemblerFeedGapFill(b *testing.B) {
	now := time.Unix(1, 0).UTC()
	first := []byte{0x01, 0x02}
	missing := []byte{0x03, 0x04, 0x05}
	last := []byte{0x06, 0x07}

	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		r := newReassembler(64*1024, time.Minute)
		r.feed("bench-gap", position{kind: posSeq, seq: 100}, first, now, true, false)
		r.feed("bench-gap", position{kind: posSeq, seq: 105}, last, now, true, false)
		r.feed("bench-gap", position{kind: posSeq, seq: 102}, missing, now, true, false)
	}
}
