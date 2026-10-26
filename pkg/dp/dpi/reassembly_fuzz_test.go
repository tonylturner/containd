// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

package dpi

import (
	"testing"
	"time"
)

func FuzzReassemblerFeed(f *testing.F) {
	f.Add([]byte{0x01, 0x02}, uint32(100), []byte{0x03, 0x04}, uint32(102), uint16(4096), uint8(0), true, false)
	f.Add([]byte{0x01, 0x02}, uint32(100), []byte{0x05, 0x06}, uint32(105), uint16(8), uint8(2), false, false)
	f.Add([]byte{0x01, 0x02}, uint32(100), []byte{0x01, 0x09}, uint32(100), uint16(8), uint8(1), true, false)
	f.Add([]byte{}, uint32(0), []byte{}, uint32(0), uint16(1), uint8(0), false, false)
	f.Add([]byte{0x01, 0x02, 0x03}, uint32(100), []byte{0x01, 0x09}, uint32(100), uint16(8), uint8(3), true, true)

	f.Fuzz(func(t *testing.T, seg1 []byte, seq1 uint32, seg2 []byte, seq2 uint32, maxSize uint16, trim uint8, strict, verify bool) {
		if maxSize == 0 {
			maxSize = 1
		}
		if len(seg1) > 1024 {
			seg1 = seg1[:1024]
		}
		if len(seg2) > 1024 {
			seg2 = seg2[:1024]
		}

		r := newReassembler(int(maxSize), time.Second)
		now := time.Unix(1, 0).UTC()
		check := func(step string, res feedResult) {
			if strict && res.err == nil && len(res.buf) > int(maxSize) {
				t.Fatalf("%s: strict buffer %d exceeds %d without an error", step, len(res.buf), maxSize)
			}
			if !strict && res.err != nil {
				t.Fatalf("%s: lenient stream returned %v", step, res.err)
			}
			if _, held := r.stats(); held != storedTotal(r) || held < 0 {
				t.Fatalf("%s: bytes buffered %d, stored %d", step, held, storedTotal(r))
			}
			r.mu.Lock()
			for _, s := range r.streams {
				if len(s.hist) > int(maxSize) || (!s.verify && len(s.hist) > 0) {
					t.Fatalf("%s: history %d bytes (verify %v), bound %d", step, len(s.hist), s.verify, maxSize)
				}
			}
			r.mu.Unlock()
		}

		res := r.feed("flow1", position{kind: posSeq, seq: seq1}, seg1, now, strict, false, verify)
		check("feed1", res)
		if res.err != nil {
			r.complete("flow1")
		}
		res = r.feed("flow1", position{kind: posSeq, seq: seq2}, seg2, now.Add(time.Millisecond), strict, false, verify)
		check("feed2", res)
		r.trim("flow1", res.base, int(trim))
		check("trim", res)
		r.sweep(now.Add(2 * time.Second))
		check("feed3", r.feed("flow1", position{kind: posSeq, seq: seq1}, seg1, now.Add(3*time.Second), strict, false, verify))
		r.complete("flow1")

		if streams, held := r.stats(); streams != 0 || held != 0 {
			t.Fatalf("after complete: %d streams, %d bytes", streams, held)
		}
	})
}
