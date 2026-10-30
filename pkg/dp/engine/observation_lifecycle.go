// SPDX-License-Identifier: Apache-2.0

package engine

import (
	"github.com/tonylturner/containd/pkg/dp/flow"
	"github.com/tonylturner/containd/pkg/dp/identify"
)

// The IEC table may reuse its directional states across wire incarnations.
// Recycle only observer-owned state, retaining every legacy lifecycle field.
// Caller holds flowMu; records must be collected before reopening the marker.
func (e *Engine) retireObservationLocked(st *flow.State, incoming *flow.Connection) {
	if live, c := e.observation, st.Connection.Load(); live != nil && c != nil {
		key := identify.Key(c.Key)
		if ctx := live.entries[key]; ctx != nil {
			e.observationPending = append(e.observationPending, live.records(live.observer.Release(key))...)
			ports := [2]uint16{st.Key.SrcPort, st.Key.DstPort}
			if c.Direction(st.Key) == flow.DirReverse {
				ports[0], ports[1] = ports[1], ports[0]
			}
			ctx.refused = !live.observer.Open(key, identify.Meta{Transport: st.Key.Proto, Ports: ports})
			if incoming != nil && incoming.Evidence != nil {
				ctx.generation = incoming.Evidence
			}
			live.syncMetrics()
		}
	}
}

// flowMu -> observer -> manager. Context survives a single direction's expiry
// so that the other direction cannot reopen a retired marker.
func (e *Engine) releaseObservationLocked(st *flow.State) {
	live := e.observation
	c := st.Connection.Load()
	if live == nil || c == nil {
		return
	}
	key := identify.Key(c.Key)
	ctx := live.entries[key]
	if ctx == nil {
		return
	}
	e.observationPending = append(e.observationPending, live.records(live.observer.Finish(key))...)
	for dir, state := range ctx.states {
		if state == st {
			ctx.states[dir] = nil
		}
	}
	ctx.refused = true
	if ctx.states[0] == nil && ctx.states[1] == nil {
		live.observer.Release(key)
		delete(live.entries, key)
	}
	live.syncMetrics()
}

func (e *Engine) finishObservation(st *flow.State) {
	e.flowMu.Lock()
	var records []observationRecord
	if live, c := e.observation, st.Connection.Load(); live != nil && c != nil {
		records = append(e.observationPending, live.records(live.observer.Finish(identify.Key(c.Key)))...)
		e.observationPending = nil
		live.syncMetrics()
	}
	e.flowMu.Unlock()
	e.recordObservations(records)
}

func (e *Engine) adoptObservationLocked(incoming, previous *flow.Connection) {
	live := e.observation
	if live == nil {
		return
	}
	from, to := identify.Key(previous.Key), identify.Key(incoming.Key)
	ctx := live.entries[from]
	if ctx == nil {
		return
	}
	remap := identify.Remap{0, 1}
	for d, state := range ctx.states {
		if state != nil {
			remap[d] = uint8(incoming.Direction(state.Key))
			remap[1-d] = 1 - remap[d]
			break
		}
	}
	output := live.observer.Adopt(from, to, remap)
	e.observationPending = append(e.observationPending, live.records(output)...)
	if target := live.entries[to]; target == nil {
		if remap[0] == 1 {
			ctx.states[0], ctx.states[1] = ctx.states[1], ctx.states[0]
		}
		live.entries[to] = ctx
	} else {
		for d, state := range ctx.states {
			if state != nil {
				target.states[remap[d]] = state
			}
		}
	}
	delete(live.entries, from)
	live.syncMetrics()
}

func (e *Engine) observationBound(state *flow.State) bool {
	if state == nil {
		return false
	}
	e.flowMu.Lock()
	defer e.flowMu.Unlock()
	c := state.Connection.Load()
	if c == nil || e.observation == nil {
		return false
	}
	status, ok := e.observation.observer.Lookup(identify.Key(c.Key))
	return ok && status.Observed
}
