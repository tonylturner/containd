// SPDX-License-Identifier: Apache-2.0

package stats

import (
	"container/heap"
	"sort"
	"time"
)

// TopTalkers describes exact counters for retained directional host-pair rows.
type TopTalkers struct {
	Semantics string      `json:"semantics"`
	Limit     int         `json:"limit"`
	Retained  int         `json:"retained"`
	Evicted   uint64      `json:"evicted"`
	Since     time.Time   `json:"since"`
	Complete  bool        `json:"complete"`
	Rows      []FlowStats `json:"rows"`
}

func talkerBefore(a, b FlowStats) bool {
	if a.Bytes != b.Bytes {
		return a.Bytes > b.Bytes
	}
	if a.SrcIP != b.SrcIP {
		return a.SrcIP < b.SrcIP
	}
	if a.DstIP != b.DstIP {
		return a.DstIP < b.DstIP
	}
	return a.Protocol < b.Protocol
}

// talkerHeap holds the worst selected row at its root.
type talkerHeap []FlowStats

func (h talkerHeap) Len() int           { return len(h) }
func (h talkerHeap) Less(i, j int) bool { return talkerBefore(h[j], h[i]) }
func (h talkerHeap) Swap(i, j int)      { h[i], h[j] = h[j], h[i] }
func (h *talkerHeap) Push(v any)        { *h = append(*h, v.(FlowStats)) }
func (h *talkerHeap) Pop() any          { old := *h; v := old[len(old)-1]; *h = old[:len(old)-1]; return v }

// TopTalkers selects at most n rows in O(retained log n) time and O(n) space.
// n <= 0 returns all rows retained by the tracker.
func (t *Tracker) TopTalkers(n int) TopTalkers {
	out := TopTalkers{Semantics: "recent", Rows: []FlowStats{}}
	if t == nil {
		return out
	}
	t.mu.RLock()
	defer t.mu.RUnlock()
	out.Limit = t.topTalkerLimit()
	out.Since = t.since
	out.Retained = len(t.flows)
	out.Evicted = t.evicted
	out.Complete = t.evicted == 0
	if n <= 0 || n > out.Retained {
		n = out.Retained
	}
	h := make(talkerHeap, 0, n)
	for _, fs := range t.flows {
		if len(h) < n {
			heap.Push(&h, *fs)
		} else if n > 0 && talkerBefore(*fs, h[0]) {
			h[0] = *fs
			heap.Fix(&h, 0)
		}
	}
	sort.Slice(h, func(i, j int) bool { return talkerBefore(h[i], h[j]) })
	out.Rows = []FlowStats(h)
	return out
}
