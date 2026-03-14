// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

package dpi

import (
	"testing"
	"time"
)

func BenchmarkReassemblerFeedInOrder(b *testing.B) {
	r := NewReassembler(64*1024, time.Minute)
	now := time.Unix(1, 0).UTC()
	payload := []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06}

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		seq := uint32(100 + (i * len(payload)))
		r.Feed("bench-in-order", payload, now, seq)
	}
}

func BenchmarkReassemblerFeedGapFill(b *testing.B) {
	now := time.Unix(1, 0).UTC()
	first := []byte{0x01, 0x02}
	missing := []byte{0x03, 0x04, 0x05}
	last := []byte{0x06, 0x07}

	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		r := NewReassembler(64*1024, time.Minute)
		r.Feed("bench-gap", first, now, 100)
		r.Feed("bench-gap", last, now, 105)
		r.Feed("bench-gap", missing, now, 102)
	}
}
