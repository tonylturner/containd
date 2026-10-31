// SPDX-License-Identifier: Apache-2.0

package engine

import (
	"container/heap"
	"time"

	"github.com/tonylturner/containd/pkg/dp/conntrack"
)

// One heap node per tuple, not per refresh: both the index and heap stay
// bounded by the alias capacity even under repeated failed lookups.
type transportExpiryEntry struct {
	tuple conntrack.Tuple
	at    time.Time
}

type transportExpiry struct {
	entries []transportExpiryEntry
	index   map[conntrack.Tuple]int
}

func (h transportExpiry) Len() int           { return len(h.entries) }
func (h transportExpiry) Less(i, j int) bool { return h.entries[i].at.Before(h.entries[j].at) }
func (h transportExpiry) Swap(i, j int) {
	h.entries[i], h.entries[j] = h.entries[j], h.entries[i]
	h.index[h.entries[i].tuple], h.index[h.entries[j].tuple] = i, j
}
func (h *transportExpiry) Push(x any) {
	entry := x.(transportExpiryEntry)
	h.index[entry.tuple] = len(h.entries)
	h.entries = append(h.entries, entry)
}
func (h *transportExpiry) Pop() any {
	last := len(h.entries) - 1
	entry := h.entries[last]
	h.entries[last] = transportExpiryEntry{}
	h.entries = h.entries[:last]
	delete(h.index, entry.tuple)
	return entry
}

func aliasPruneTime(a *transportAlias) time.Time {
	if a.connection.Verified() {
		// Resolved aliases retain incarnation history for 30 seconds past
		// the lookup TTL. The old scan used a strict greater-than comparison.
		return a.expires.Add(30*time.Second + time.Nanosecond)
	}
	return a.expires
}

func (r *transportResolver) pruneAliases(now time.Time) {
	h := &r.expiry
	if h.index == nil {
		// Build once on first miss, including any preseeded aliases.
		h.index = make(map[conntrack.Tuple]int, len(r.aliases))
		for tuple, alias := range r.aliases {
			h.index[tuple] = len(h.entries)
			h.entries = append(h.entries, transportExpiryEntry{tuple, aliasPruneTime(alias)})
		}
		heap.Init(h)
	}
	for h.Len() > 0 && !now.Before(h.entries[0].at) {
		entry := heap.Pop(h).(transportExpiryEntry)
		delete(r.aliases, entry.tuple)
	}
}

func (r *transportResolver) storeAlias(tuple conntrack.Tuple, alias *transportAlias) {
	r.aliases[tuple] = alias
	h := &r.expiry
	entry := transportExpiryEntry{tuple, aliasPruneTime(alias)}
	if i, ok := h.index[tuple]; ok {
		h.entries[i] = entry
		heap.Fix(h, i)
	} else {
		heap.Push(h, entry)
	}
}
