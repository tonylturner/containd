// SPDX-License-Identifier: Apache-2.0

package identify

import (
	"bytes"
	"math/rand"
	"testing"
)

func TestPrefixRangeMerging(t *testing.T) {
	data := []byte("abcdefghijklmnopqrstuvwxyz")
	for _, offsets := range [][]span{
		{{10, 12}, {20, 22}, {14, 16}, {10, 22}, {0, 26}},
		{{0, 10}, {15, 20}, {10, 15}, {20, 26}},
		{{10, 20}, {12, 18}, {0, 26}},
		{{20, 26}, {10, 20}, {0, 10}},
	} {
		p := prefix{base: 100, syn: true, data: make([]byte, 26), ranges: make([]span, 0, 9)}
		for _, r := range offsets {
			if _, reason := p.add(100+uint32(r.start), data[r.start:r.end], 8); reason != "" {
				t.Fatal(reason)
			}
		}
		if p.length != len(data) || !bytes.Equal(p.data, data) || len(p.ranges) != 1 {
			t.Fatal(p)
		}
	}
}

func FuzzPrefix(f *testing.F) {
	f.Add(uint64(104))
	f.Fuzz(func(t *testing.T, seed uint64) {
		random := rand.New(rand.NewSource(int64(seed)))
		raw := make([]byte, 128)
		_, _ = random.Read(raw)
		p := prefix{base: ^uint32(0) - 31, syn: true, data: make([]byte, len(raw)), ranges: make([]span, 0, 129)}
		present := make([]bool, len(raw))
		for range 256 {
			start := random.Intn(len(raw))
			end := start + 1 + random.Intn(len(raw)-start)
			if _, reason := p.add(p.base+uint32(start), raw[start:end], 128); reason != "" {
				t.Fatal(reason)
			}
			for i := start; i < end; i++ {
				present[i] = true
			}
			want := 0
			for want < len(raw) && present[want] {
				want++
			}
			if p.length != want || !bytes.Equal(p.data[:want], raw[:want]) {
				t.Fatalf("length %d want %d", p.length, want)
			}
			if len(p.ranges) > 129 {
				t.Fatal("unbounded ranges")
			}
		}
	})
}
