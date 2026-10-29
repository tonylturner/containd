// SPDX-License-Identifier: Apache-2.0

package identify

import (
	"fmt"
	"time"
	"unsafe"

	"github.com/tonylturner/containd/pkg/dp/ics"
)

type entry struct {
	meta      Meta
	prefixes  [2]prefix
	datagrams []Datagram
	opened    time.Time
	first     time.Time
	started   bool
	arrivals  int
	decision  Decision
	taken     bool
	candidate bool
	ambiguous bool
}

// EntryCharge includes the inline entry, key and a conservative 128-byte map
// slot/allocator allowance. ChargedBytes is deterministic admission accounting,
// not a claim about total process RSS or Go map bucket allocations.
const EntryCharge = int(unsafe.Sizeof(entry{})) + int(unsafe.Sizeof(Key{})) + 128

type Table struct {
	budgets Budgets
	now     func() time.Time
	entries map[Key]*entry
	charged int
	counts  Counters
}

// NewTable requires positive budgets and an injected monotonic ingestion clock.
// time.Now is suitable live; deterministic replay should supply its own clock.
func NewTable(b Budgets, now func() time.Time) (*Table, error) {
	if now == nil || b.BytesPerDirection <= 0 || b.PendingRanges < 0 || b.Arrivals <= 0 ||
		b.Duration <= 0 || b.UDPDatagrams <= 0 || b.Entries <= 0 || b.ChargedBytes < EntryCharge {
		return nil, fmt.Errorf("invalid identification budgets or clock")
	}
	// Ensure capacity arithmetic cannot overflow and one allocation can fit.
	if b.BytesPerDirection > b.ChargedBytes ||
		b.PendingRanges > b.ChargedBytes/int(unsafe.Sizeof(span{}))-1 ||
		b.UDPDatagrams > b.ChargedBytes/int(unsafe.Sizeof(Datagram{})) {
		return nil, fmt.Errorf("identification capacities exceed charged-byte budget")
	}
	return &Table{budgets: b, now: now, entries: make(map[Key]*entry)}, nil
}

// Open admits an incarnation, without allocating prefix storage. Existing keys
// are never overwritten (even terminal ones); Release before reuse.
func (t *Table) Open(key Key, meta Meta) bool {
	if meta.Transport != ics.TCP && meta.Transport != ics.UDP {
		return false
	}
	if _, exists := t.entries[key]; exists {
		return false
	}
	if len(t.entries) == t.budgets.Entries || EntryCharge > t.budgets.ChargedBytes-t.charged {
		t.counts.Overflow++
		return false
	}
	e := &entry{meta: meta, opened: t.now(), decision: Decision{State: NeedMore}}
	for d, port := range meta.Ports {
		for _, p := range protocols {
			if !(meta.Transport == ics.UDP && port == ics.CIPImplicitPort) &&
				ics.IsProtocolPortOn(string(p), meta.Transport, port) {
				e.decision.Expected[d] = p
			}
		}
	}
	t.entries[key] = e
	t.charged += EntryCharge
	return true
}

func terminal(s State) bool { return s == Reject || s == Confirmed || s == Incomplete }

// Observe consumes SYN metadata and payload. ACK-only arrivals cost no payload
// work. The caller feeds both SYN and SYN-ACK, including any SYN-carried bytes.
// A missing key or invalid direction returns false without creating state.
func (t *Table) Observe(key Key, a Arrival) (Decision, bool) {
	e, ok := t.entries[key]
	if !ok || a.Direction > 1 {
		return Decision{}, false
	}
	if terminal(e.decision.State) {
		return e.decision, true
	}
	if t.expire(e, t.now()) {
		return e.decision, true
	}
	p := &e.prefixes[a.Direction]
	sequence := a.Sequence
	if e.meta.Transport == ics.TCP && a.SYN {
		sequence++
		if p.syn && p.base != sequence {
			t.finish(e, Conflict)
			return e.decision, true
		}
		p.syn, p.base = true, sequence
	}
	if a.Truncated {
		t.finish(e, Truncated)
		return e.decision, true
	}
	if len(a.Payload) == 0 {
		if e.meta.Transport != ics.UDP {
			return e.decision, true
		}
		if len(e.datagrams) == 0 {
			t.decide(e, true) // reject an empty first datagram without allocating
			return e.decision, true
		}
	}
	if !e.started {
		e.first, e.started = t.now(), true
	}
	if e.meta.Transport == ics.TCP && !p.syn {
		t.finish(e, Midstream)
		return e.decision, true
	}
	if len(a.Payload) > 0 {
		e.arrivals++
	}
	if len(a.Payload) > 0 && !t.allocate(e, p) {
		t.counts.Overflow++
		t.finish(e, Budget)
		return e.decision, true
	}
	changed := true
	var coverage Coverage
	payload := a.Payload
	available := len(p.data) - p.length
	if e.meta.Transport == ics.TCP {
		start := int(int32(sequence - p.base))
		if start < 0 {
			t.finish(e, Conflict)
			return e.decision, true
		}
		available = max(0, len(p.data)-start)
	}
	clipped := len(payload) > available
	if clipped {
		payload = payload[:available]
	}
	if e.meta.Transport == ics.UDP {
		start := p.length
		p.length += copy(p.data[start:], payload)
		e.datagrams = append(e.datagrams, Datagram{a.Direction, Range{start, p.length}, len(a.Payload)})
	} else if len(payload) > 0 {
		changed, coverage = p.add(sequence, payload, t.budgets.PendingRanges)
	}
	if coverage != "" {
		t.finish(e, coverage)
	} else if clipped {
		t.decide(e, false)
		if e.decision.State != Reject {
			t.finish(e, Budget)
		}
	} else if changed {
		t.decide(e, true)
	}
	// The last allowed arrival can confirm. Otherwise it exhausts the budget;
	// callers do not need to invent an extra packet to learn about exhaustion.
	if !terminal(e.decision.State) && (e.arrivals == t.budgets.Arrivals ||
		e.meta.Transport == ics.UDP && len(e.datagrams) == t.budgets.UDPDatagrams ||
		e.prefixes[0].length == t.budgets.BytesPerDirection &&
			e.prefixes[1].length == t.budgets.BytesPerDirection) {
		t.finish(e, Budget)
	}
	return e.decision, true
}

func (t *Table) allocate(e *entry, p *prefix) bool {
	charge, available := 0, t.budgets.ChargedBytes-t.charged
	if p.data == nil {
		if t.budgets.BytesPerDirection > available {
			return false
		}
		charge = t.budgets.BytesPerDirection
		if e.meta.Transport == ics.TCP {
			n := (t.budgets.PendingRanges + 1) * int(unsafe.Sizeof(span{}))
			if n > available-charge {
				return false
			}
			charge += n
		}
	}
	if e.meta.Transport == ics.UDP && e.datagrams == nil {
		n := t.budgets.UDPDatagrams * int(unsafe.Sizeof(Datagram{}))
		if n > available-charge {
			return false
		}
		charge += n
	}
	if p.data == nil {
		p.data = make([]byte, t.budgets.BytesPerDirection)
		if e.meta.Transport == ics.TCP {
			p.ranges = make([]span, 0, t.budgets.PendingRanges+1)
		}
	}
	if e.meta.Transport == ics.UDP && e.datagrams == nil {
		e.datagrams = make([]Datagram, 0, t.budgets.UDPDatagrams)
	}
	t.charged += charge
	return true
}

func (t *Table) decide(e *entry, complete bool) {
	active, confirmed, waiting := 0, 0, false
	for i, p := range protocols {
		var r Result
		if e.meta.Transport == ics.UDP {
			r = udpResult(e, p)
		} else {
			r = Probe(p, e.meta.Transport,
				e.prefixes[0].data[:e.prefixes[0].length], e.prefixes[1].data[:e.prefixes[1].length])
		}
		e.decision.Results[i] = r
		if r.State == NeedMore {
			waiting = true
		}
		if r.State == Candidate || r.State == Confirmed {
			active++
			e.decision.Protocol = p
			if r.State == Confirmed {
				confirmed++
			}
		}
	}
	switch {
	case active > 1:
		e.decision.State, e.decision.Protocol = Ambiguous, ""
		if !e.ambiguous {
			t.counts.Ambiguity++
			e.ambiguous = true
		}
	case active == 1:
		e.decision.State = Candidate
		if !e.candidate {
			t.counts.Candidates++
			e.candidate = true
		}
		if confirmed == 1 && complete {
			e.decision.State = Confirmed
			t.counts.Confirms++
		}
	case waiting:
		e.decision.State, e.decision.Protocol = NeedMore, ""
	default:
		e.decision.State, e.decision.Protocol = Reject, ""
		t.counts.Rejects++
	}
}

func udpResult(e *entry, protocol Protocol) Result {
	if len(e.datagrams) == 0 {
		return Probe(protocol, e.meta.Transport, nil, nil)
	}
	best := udpProbe(e, protocol, e.datagrams[0], nil)
	states := [2]State{NeedMore, NeedMore}
	var examined [2]Range
	for _, a := range e.datagrams {
		r := udpProbe(e, protocol, a, nil)
		state := r.States[a.Direction]
		if state == Reject || states[a.Direction] != Reject && strength(state) > strength(states[a.Direction]) {
			states[a.Direction] = state
		}
		examined[a.Direction].End = max(examined[a.Direction].End, a.Range.End)
		if strength(r.State) > strength(best.State) {
			best = r
		}
		for _, b := range e.datagrams {
			if a.Direction == b.Direction {
				continue
			}
			r := udpProbe(e, protocol, a, &b)
			if strength(r.State) > strength(best.State) {
				best = r
			}
		}
	}
	best.States, best.Examined = states, examined
	if best.State == Confirmed && (states[0] == Reject || states[1] == Reject) {
		best.State, best.Reason = Candidate, "contradictory datagram evidence"
	}
	return best
}

func udpProbe(e *entry, protocol Protocol, a Datagram, b *Datagram) Result {
	var other []byte
	lengths := [2]int{a.Length, 0}
	if b != nil {
		other = datagramBytes(e, *b)
		lengths[1] = b.Length
	}
	r := probe(protocol, e.meta.Transport, datagramBytes(e, a), other, lengths)
	r.Examined[0].Start += a.Range.Start
	r.Examined[0].End += a.Range.Start
	if b != nil {
		r.Examined[1].Start += b.Range.Start
		r.Examined[1].End += b.Range.Start
	}
	if a.Direction == 1 {
		r.Examined[0], r.Examined[1] = r.Examined[1], r.Examined[0]
		r.States[0], r.States[1] = r.States[1], r.States[0]
		if r.Role == Client {
			r.Role = Server
		} else if r.Role == Server {
			r.Role = Client
		}
	}
	return r
}

func datagramBytes(e *entry, d Datagram) []byte {
	return e.prefixes[d.Direction].data[d.Range.Start:d.Range.End]
}

func (t *Table) finish(e *entry, reason Coverage) {
	e.decision.State, e.decision.Coverage = Incomplete, reason
	for i, r := range [...]Coverage{Budget, Timeout, Conflict, Midstream, Truncated} {
		if r == reason {
			t.counts.Incomplete[i]++
		}
	}
}

func (t *Table) expire(e *entry, now time.Time) bool {
	first := e.opened
	if e.started {
		first = e.first
	}
	if !terminal(e.decision.State) && now.Sub(first) >= t.budgets.Duration {
		t.finish(e, Timeout)
	}
	return terminal(e.decision.State)
}

// Poll applies timeouts even when no new payload arrives. The caller schedules
// polling; there are no background workers or wall-clock sleeps.
func (t *Table) Poll(key Key) (Decision, bool) {
	e, ok := t.entries[key]
	if !ok {
		return Decision{}, false
	}
	t.expire(e, t.now())
	return e.decision, true
}

// Sweep expires all pending deadlines in the injected ingestion clock's domain.
// It returns newly expired keys for the caller to Poll/Take and Release. Like
// Poll, it preserves terminal decisions until explicit Release, not eviction.
func (t *Table) Sweep(now time.Time) []Key {
	var expired []Key
	for key, e := range t.entries {
		if !terminal(e.decision.State) && t.expire(e, now) {
			expired = append(expired, key)
		}
	}
	return expired
}

// Take transfers the retained prefix exactly once for a terminal decision.
// Terminal metadata remains cached, bounded and charged until Release.
func (t *Table) Take(key Key) (Decision, Replay, bool) {
	e, ok := t.entries[key]
	if !ok || e.taken || !terminal(e.decision.State) {
		return Decision{}, Replay{}, false
	}
	replay := Replay{Datagrams: e.datagrams}
	t.charged -= retainedCharge(e)
	e.datagrams = nil
	for i := range e.prefixes {
		p := &e.prefixes[i]
		replay.Bytes[i] = p.data[:p.length:p.length]
		replay.Sequence[i] = p.base
		for _, r := range p.ranges {
			if r.start >= p.length {
				replay.Pending[i] = append(replay.Pending[i], Segment{
					Sequence: p.base + uint32(r.start),
					Bytes:    p.data[r.start:r.end:r.end],
				})
			}
		}
		p.data, p.ranges, p.length = nil, nil, 0
	}
	e.taken = true
	return e.decision, replay, true
}

func retainedCharge(e *entry) int {
	n := cap(e.datagrams) * int(unsafe.Sizeof(Datagram{}))
	for _, p := range e.prefixes {
		n += cap(p.data) + cap(p.ranges)*int(unsafe.Sizeof(span{}))
	}
	return n
}

func (t *Table) Release(key Key) {
	if e, ok := t.entries[key]; ok {
		t.charged -= EntryCharge + retainedCharge(e)
		delete(t.entries, key)
	}
}

func (t *Table) Counters() Counters          { return t.counts }
func (t *Table) Usage() (entries, bytes int) { return len(t.entries), t.charged }
