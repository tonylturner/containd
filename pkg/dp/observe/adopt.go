// SPDX-License-Identifier: Apache-2.0

package observe

import (
	"sort"

	"github.com/tonylturner/containd/pkg/dp/identify"
)

// Adopt merges transport-pending identities. Remap maps from's directions to
// to's directions. Frozen session ids and client/server roles never change.
// Conflicting bindings are ended with a counted coverage conflict, not a second
// identification event. Pending conflicts emit each incarnation's first event.
func (o *Observer) Adopt(from, to identify.Key, remap identify.Remap) Output {
	o.mu.Lock()
	defer o.mu.Unlock()
	a, b := o.entries[from], o.entries[to]
	if o.drained || a == nil || from == to || to == "" || !remap.Valid() {
		return Output{}
	}
	if b == nil {
		if a.ended == 0 {
			o.table.Adopt(from, to, remap)
		}
		remapConnection(a, remap)
		o.entries[to] = a
		delete(o.entries, from)
		return Output{}
	}
	if a.binding == Observation && b.binding == Observation && a.protocol != b.protocol {
		o.endBinding(a)
		o.endBinding(b)
		a.coverage, b.coverage = identify.Conflict, identify.Conflict
		o.counts.AdoptionConflicts++
		delete(o.entries, from)
		return Output{}
	}
	// All completed entries are markers, including a live observation binding.
	// The earlier terminal survives; a pending partner is released silently.
	if a.ended != 0 || b.ended != 0 {
		observed := a.observed || b.observed
		fins := b.fin
		for d, dst := range remap {
			fins[dst] = fins[dst] || a.fin[d]
		}
		if a.ended != 0 && (b.ended == 0 || a.ended < b.ended) {
			o.endBinding(b)
			o.table.Release(to)
			remapConnection(a, remap)
			o.entries[to] = a
		} else {
			o.endBinding(a)
			o.table.Release(from)
		}
		survivor := o.entries[to]
		survivor.observed, survivor.fin = observed, fins
		if fins[0] && fins[1] {
			o.endBinding(survivor)
		}
		delete(o.entries, from)
		return Output{}
	}
	for d, dst := range remap {
		if a.roles[d] != 0 && b.roles[dst] != 0 && a.roles[d] != b.roles[dst] {
			o.table.Abort(from, identify.Conflict)
			o.table.Abort(to, identify.Conflict)
			o.counts.AdoptionConflicts++
			out := o.consume(from, a)
			out.append(o.consume(to, b))
			delete(o.entries, from)
			return out
		}
	}
	result, ok := o.table.Adopt(from, to, remap)
	if !ok {
		return Output{}
	}
	if result.Conflict {
		o.counts.AdoptionConflicts++
		out := o.consume(from, a)
		out.append(o.consume(to, b))
		delete(o.entries, from)
		return out
	}
	remapConnection(a, remap)
	for d := range 2 {
		b.fin[d] = b.fin[d] || a.fin[d]
		if a.syn[d] {
			b.syn[d], b.base[d], b.roles[d] = true, a.base[d], a.roles[d]
		}
		if a.at[d].After(b.at[d]) {
			b.at[d], b.states[d] = a.at[d], a.states[d]
		}
	}
	b.stamps = append(b.stamps, a.stamps...)
	sort.Slice(b.stamps, func(i, j int) bool { return b.stamps[i].order < b.stamps[j].order })
	delete(o.entries, from)
	out := o.consume(to, b)
	if b.fin[0] && b.fin[1] {
		o.table.Finish(to)
		out.append(o.consume(to, b))
		o.endBinding(b)
	}
	return out
}

func remapConnection(c *connection, r identify.Remap) {
	if r[0] == 0 {
		return
	}
	c.meta.Ports[0], c.meta.Ports[1] = c.meta.Ports[1], c.meta.Ports[0]
	c.syn[0], c.syn[1] = c.syn[1], c.syn[0]
	c.base[0], c.base[1] = c.base[1], c.base[0]
	c.high[0], c.high[1] = c.high[1], c.high[0]
	c.roles[0], c.roles[1] = c.roles[1], c.roles[0]
	c.states[0], c.states[1] = c.states[1], c.states[0]
	c.at[0], c.at[1] = c.at[1], c.at[0]
	c.fin[0], c.fin[1] = c.fin[1], c.fin[0]
	for i := range c.stamps {
		c.stamps[i].dir = r[c.stamps[i].dir]
	}
}
