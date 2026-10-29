// SPDX-License-Identifier: Apache-2.0

package identify

import (
	"github.com/tonylturner/containd/pkg/dp/ics"
	"sort"
)

// Remap maps each source direction to a destination direction. Only identity
// and reversal are valid. It never changes a decoder's frozen session roles.
type Remap [2]uint8

func (r Remap) Valid() bool { return r == Remap{0, 1} || r == Remap{1, 0} }

// Adoption reports a merge. On Conflict both entries remain finalized for the
// caller to consume; otherwise only to survives. A terminal survivor is the
// earlier terminal, even when the source key is newer.
type Adoption struct{ Conflict bool }

// Adopt rekeys or merges from into to. Invalid or absent sources do nothing.
// Evidence disagreement finalizes both entries as Conflict without eviction.
func (t *Table) Adopt(from, to Key, remap Remap) (Adoption, bool) {
	a, ok := t.entries[from]
	if !ok || from == to || !remap.Valid() {
		return Adoption{}, false
	}
	b := t.entries[to]
	if b == nil {
		remapEntry(a, remap)
		t.entries[to] = a
		delete(t.entries, from)
		return Adoption{}, true
	}
	if terminal(a.decision.State) || terminal(b.decision.State) {
		if terminal(a.decision.State) && (!terminal(b.decision.State) || a.terminalOrder < b.terminalOrder) {
			t.Release(to)
			remapEntry(a, remap)
			t.entries[to] = a
			delete(t.entries, from)
		} else {
			t.Release(from)
		}
		return Adoption{}, true
	}
	conflict := func() (Adoption, bool) {
		t.finish(a, Conflict)
		t.finish(b, Conflict)
		return Adoption{Conflict: true}, true
	}
	if a.meta.Transport != b.meta.Transport {
		return conflict()
	}
	if a.meta.Transport == ics.UDP && len(a.datagrams)+len(b.datagrams) > t.budgets.UDPDatagrams {
		return conflict()
	}
	for d, dst := range remap {
		src, target := &a.prefixes[d], &b.prefixes[dst]
		if src.syn && target.syn && src.base != target.base {
			return conflict()
		}
		if src.syn {
			target.syn, target.base = true, src.base
		}
		if len(src.data) == 0 {
			continue
		}
		if !t.allocate(b, target) {
			t.counts.Overflow++
			return conflict()
		}
		if a.meta.Transport == ics.UDP {
			if src.length > len(target.data)-target.length {
				return conflict()
			}
			start := target.length
			target.length += copy(target.data[start:], src.data[:src.length])
			for _, dg := range a.datagrams {
				if dg.Direction != uint8(d) {
					continue
				}
				dg.Direction = dst
				dg.Range.Start += start
				dg.Range.End += start
				b.datagrams = append(b.datagrams, dg)
			}
		} else {
			for _, r := range src.ranges {
				if _, coverage := target.add(src.base+uint32(r.start), src.data[r.start:r.end], t.budgets.PendingRanges); coverage != "" {
					return conflict()
				}
			}
		}
	}
	sort.Slice(b.datagrams, func(i, j int) bool { return b.datagrams[i].order < b.datagrams[j].order })
	b.arrivals += a.arrivals
	if a.opened.Before(b.opened) {
		b.opened = a.opened
	}
	if a.started && (!b.started || a.first.Before(b.first)) {
		b.first, b.started = a.first, true
	}
	t.Release(from)
	t.decide(b, b.arrivals <= t.budgets.Arrivals)
	if !terminal(b.decision.State) && b.arrivals >= t.budgets.Arrivals {
		t.finish(b, Budget)
	}
	return Adoption{}, true
}

func remapEntry(e *entry, r Remap) {
	if r[0] == 0 {
		return
	}
	e.prefixes[0], e.prefixes[1] = e.prefixes[1], e.prefixes[0]
	e.meta.Ports[0], e.meta.Ports[1] = e.meta.Ports[1], e.meta.Ports[0]
	e.decision.Expected[0], e.decision.Expected[1] = e.decision.Expected[1], e.decision.Expected[0]
	for i := range e.decision.Results {
		x := &e.decision.Results[i]
		x.States[0], x.States[1] = x.States[1], x.States[0]
		x.Examined[0], x.Examined[1] = x.Examined[1], x.Examined[0]
		if x.Role == Client {
			x.Role = Server
		} else if x.Role == Server {
			x.Role = Client
		}
	}
	for i := range e.datagrams {
		e.datagrams[i].Direction = r[e.datagrams[i].Direction]
	}
}
