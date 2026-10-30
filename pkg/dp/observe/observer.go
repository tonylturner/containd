// SPDX-License-Identifier: Apache-2.0

package observe

import (
	"fmt"
	"time"

	"github.com/tonylturner/containd/pkg/dp/dpi"
	"github.com/tonylturner/containd/pkg/dp/ics/eventfields"
	"github.com/tonylturner/containd/pkg/dp/identify"
)

// New validates budgets and enabled decoders. It starts no workers; the caller
// supplies ingestion time and schedules Sweep, close/expiry and Drain.
func New(opts Options) (*Observer, error) {
	if opts.Markers <= 0 || opts.Manager == nil {
		return nil, fmt.Errorf("observer requires positive marker capacity and dedicated manager")
	}
	table, err := identify.NewTable(opts.Budgets, opts.Now)
	if err != nil {
		return nil, err
	}
	protocols := opts.Budgets.Protocols
	if protocols == nil {
		protocols = []identify.Protocol{identify.Modbus, identify.DNP3, identify.IEC104, identify.ENIP}
	}
	for _, p := range protocols {
		if !opts.Manager.HasProtocol(string(p)) {
			return nil, fmt.Errorf("enabled protocol %q has no observation decoder", p)
		}
	}
	return &Observer{table: table, opts: opts, entries: make(map[identify.Key]*connection)}, nil
}

func (o *Observer) Open(key identify.Key, meta identify.Meta) bool {
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.drained || key == "" || o.entries[key] != nil {
		return false
	}
	if len(o.entries) >= o.opts.Markers {
		o.counts.Refusals++
		return false
	}
	if !o.table.Open(key, meta) {
		o.counts.Refusals++
		return false
	}
	o.entries[key] = &connection{meta: meta}
	return true
}

// Observe is one transaction: evidence, binding/replay or continuation, then
// close handling. The terminal trigger is never submitted as continuation.
func (o *Observer) Observe(key identify.Key, p Packet) Output {
	o.mu.Lock()
	defer o.mu.Unlock()
	c := o.entries[key]
	if c == nil || p.Direction > 1 || o.drained {
		return Output{}
	}
	d := p.Direction
	c.states[d], c.at[d] = p.State, p.At
	var out Output
	if c.meta.Transport == 6 && p.SYN {
		role := dpi.ClientToServer
		if p.SYNACK {
			role = dpi.ServerToClient
		}
		if c.syn[d] && (c.base[d] != p.Sequence+1 || c.roles[d] != role) || c.roles[1-d] == role {
			if c.ended == 0 {
				o.table.Abort(key, identify.Conflict)
				out = o.consume(key, c)
			} else {
				o.endBinding(c)
				c.coverage = identify.Conflict
				o.counts.AdoptionConflicts++
			}
			return out
		}
		c.syn[d], c.base[d], c.roles[d] = true, p.Sequence+1, role
		c.roles[1-d] = dpi.ClientToServer
		if role == dpi.ClientToServer {
			c.roles[1-d] = dpi.ServerToClient
		}
	}
	if c.ended == 0 {
		if len(p.Payload) > 0 || c.meta.Transport == 17 {
			o.serial++
			seq := p.Sequence
			if p.SYN {
				seq++
			}
			c.stamps = append(c.stamps, stamp{d, seq, len(p.Payload), p.At, p.State, o.serial})
		}
		o.table.Observe(key, p.Arrival)
		out.append(o.consume(key, c))
	} else if c.binding == Observation && (len(p.Payload) > 0 || c.meta.Transport == 17) {
		if p.Truncated {
			c.coverage = identify.Truncated
			o.endBinding(c)
			out.Batches = append(out.Batches, Batch{Key: key, Dir: d, State: p.State, At: p.At, Err: fmt.Errorf("observation arrival is truncated")})
		} else {
			seq := p.Sequence
			if p.SYN {
				seq++
			}
			out.Batches = append(out.Batches, o.decode(key, c, stamp{dir: d, seq: seq, at: p.At, state: p.State}, p.Payload))
		}
	}
	if p.FIN {
		c.fin[d] = true
	}
	if p.RST || c.fin[0] && c.fin[1] {
		if c.ended == 0 {
			o.table.Finish(key)
			out.append(o.consume(key, c))
		}
		o.endBinding(c)
	}
	return out
}

func (o *Observer) consume(key identify.Key, c *connection) Output {
	d, replay, ok := o.table.Take(key)
	if !ok {
		return Output{}
	}
	c.binding, c.protocol, c.coverage = None, d.Protocol, d.Coverage
	if d.State == identify.Confirmed {
		c.binding = Observation
		if o.opts.LegacyDecodes != nil && o.opts.LegacyDecodes(key, d.Protocol) {
			c.binding = Legacy
		}
	}
	o.serial++
	c.ended = o.serial
	c.session = fmt.Sprintf("observe/%d/%s/%s", o.serial, key, d.Protocol)
	at := c.at[0]
	if c.at[1].After(at) {
		at = c.at[1]
	}
	if at.IsZero() {
		at = o.opts.Now()
	}
	scope := any("unknown")
	if o.opts.Scope != nil {
		scope = o.opts.Scope(key, d.Protocol)
	}
	ev := IdentificationEvent(d, c.meta, c.syn, c.binding, scope, at)
	// SYN roles, not content guesses, identify the server endpoint on alternate ports.
	for dir, role := range c.roles {
		if role == dpi.ServerToClient {
			ev.Attributes[eventfields.KeyServicePort] = c.meta.Ports[dir]
		}
	}
	for _, state := range c.states {
		if state != nil {
			ev.FlowID = state.ID()
			break
		}
	}
	out := Output{Identifications: []Identification{{key, d, c.binding, ev}}}
	row, col := 4, 2
	for i, p := range []identify.Protocol{identify.Modbus, identify.DNP3, identify.IEC104, identify.ENIP} {
		if d.Protocol == p {
			row = i
		}
	}
	if d.State == identify.Confirmed {
		col = 0
	} else if d.State == identify.Reject {
		col = 1
	}
	o.counts.Outcomes[row][col]++
	if c.binding == Observation {
		c.observed = true
		out.Batches = o.replay(key, c, replay)
	}
	c.stamps = nil
	o.table.Release(key)
	return out
}

func (o *Observer) endBinding(c *connection) {
	if c.binding == Observation {
		o.opts.Manager.EndStream(c.session)
		c.binding = None
	}
}

func (o *Observer) Sweep(now time.Time) Output {
	o.mu.Lock()
	defer o.mu.Unlock()
	var out Output
	for _, key := range o.table.Sweep(now) {
		out.append(o.consume(key, o.entries[key]))
	}
	return out
}

// Stop discards evidence and ends passive decoding after a capture loss.
// Unlike Finish, it never replays pending bytes or emits decoder events.
// The terminal marker survives until Release, so it cannot be reopened.
func (o *Observer) Stop(key identify.Key) {
	o.mu.Lock()
	defer o.mu.Unlock()
	c := o.entries[key]
	if c == nil {
		return
	}
	o.table.Release(key)
	c.stamps = nil
	c.coverage = identify.Truncated
	o.serial++
	c.ended = o.serial
	o.endBinding(c)
	c.binding = None
}

// Finish ends a binding and finalizes pending evidence, retaining the marker.
func (o *Observer) Finish(key identify.Key) Output {
	o.mu.Lock()
	defer o.mu.Unlock()
	return o.finish(key)
}
func (o *Observer) finish(key identify.Key) Output {
	c := o.entries[key]
	if c == nil {
		return Output{}
	}
	o.table.Finish(key)
	out := o.consume(key, c)
	o.endBinding(c)
	return out
}

// Release retires the entire incarnation, including its marker.
func (o *Observer) Release(key identify.Key) Output {
	o.mu.Lock()
	defer o.mu.Unlock()
	out := o.finish(key)
	delete(o.entries, key)
	return out
}

// Drain permanently closes this instance for reconfiguration, even if concurrent
// callers still hold it. A replacement needs a fresh manager and fresh decoders.
func (o *Observer) Drain() Output {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.drained = true
	var out Output
	for key := range o.entries {
		out.append(o.finish(key))
		delete(o.entries, key)
	}
	return out
}

func (o *Observer) Counters() Snapshot {
	o.mu.Lock()
	defer o.mu.Unlock()
	s := o.counts
	s.Evidence = o.table.Counters()
	s.Incomplete = s.Evidence.Incomplete
	s.Entries, s.ChargedBytes = o.table.Usage()
	s.Markers = len(o.entries)
	for _, c := range o.entries {
		if c.binding == Observation {
			s.Bindings++
		}
	}
	return s
}

// Lookup returns immutable incarnation metadata without exposing table state.
func (o *Observer) Lookup(key identify.Key) (Status, bool) {
	o.mu.Lock()
	defer o.mu.Unlock()
	c := o.entries[key]
	if c == nil {
		return Status{}, false
	}
	return Status{Observed: c.observed, Protocol: c.protocol, Binding: c.binding, Coverage: c.coverage, SYNCoverage: c.syn, Session: c.session}, true
}
