// SPDX-License-Identifier: Apache-2.0

package identify

import "bytes"

type span struct{ start, end int }

type prefix struct {
	base   uint32
	syn    bool
	data   []byte
	ranges []span // sorted, disjoint, non-adjacent coverage in data
	length int    // contiguous bytes from offset zero
}

func (p *prefix) add(sequence uint32, b []byte, limit int) (bool, Coverage) {
	start := int(int32(sequence - p.base)) // handles TCP sequence wrap
	if start < 0 {
		return false, Conflict
	}
	if start > len(p.data) || len(b) > len(p.data)-start {
		return false, Budget
	}
	end := start + len(b)
	for _, r := range p.ranges {
		lo, hi := max(start, r.start), min(end, r.end)
		if lo < hi && !bytes.Equal(p.data[lo:hi], b[lo-start:hi-start]) {
			return false, Conflict
		}
	}
	lo, hi := start, end
	first := 0
	for first < len(p.ranges) && p.ranges[first].end < lo {
		first++
	}
	last := first
	for last < len(p.ranges) && p.ranges[last].start <= hi {
		lo, hi = min(lo, p.ranges[last].start), max(hi, p.ranges[last].end)
		last++
	}
	count := len(p.ranges) - (last - first) + 1
	pending := count
	if lo == 0 || first > 0 && p.ranges[0].start == 0 {
		pending--
	}
	if pending > limit {
		return false, Budget
	}
	copy(p.data[start:end], b)
	old := len(p.ranges)
	p.ranges = p.ranges[:max(old, count)]
	copy(p.ranges[first+1:], p.ranges[last:old])
	p.ranges[first] = span{lo, hi}
	p.ranges = p.ranges[:count]
	before := p.length
	if p.ranges[0].start == 0 {
		p.length = p.ranges[0].end
	}
	return p.length != before, ""
}
