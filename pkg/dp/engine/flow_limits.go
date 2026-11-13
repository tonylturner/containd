// SPDX-License-Identifier: Apache-2.0

package engine

import (
	"time"

	"github.com/tonylturner/containd/pkg/dp/capture"
	"github.com/tonylturner/containd/pkg/dp/flow"
	"github.com/tonylturner/containd/pkg/dp/limits"
	"github.com/tonylturner/containd/pkg/dp/markabi"
)

func (e *Engine) flowCeiling(enforcing bool) int {
	if enforcing {
		return e.stateLimits.MaxFlows
	}
	return e.stateLimits.MaxFlows/4*3 + e.stateLimits.MaxFlows%4*3/4
}

// Classify without admitting a state, observation context or IEC session.
func (e *Engine) flowEnforcing(pkt capture.Packet) bool {
	if !pkt.Token.Inline() {
		return false
	}
	if pkt.HasMark {
		return pkt.Mark&markabi.EnforceScopeMark != 0
	}
	st := wireServiceState(pkt)
	return e.enforcingPacketScope(pkt, &st)
}

// Due expiry precedes creation, including refusals. Under pressure, permit one
// additional expiry pass per second; a flood cannot cause a full scan per packet.
func (e *Engine) sweepBeforeAdmission(now time.Time, enforcing bool) {
	e.flowMu.Lock()
	due := now.Sub(e.lastSweep) >= 30*time.Second
	pressure := e.flowSlots+2 > e.flowCeiling(enforcing) && now.Sub(e.lastCapacitySweep) >= time.Second
	if due {
		e.lastSweep = now
	}
	if due || pressure {
		e.lastCapacitySweep = now
	}
	e.flowMu.Unlock()
	if due || pressure {
		e.sweepFlows(now)
	}
}

func (e *Engine) refuseFlow(pkt capture.Packet) capture.Decision {
	enforcing := e.flowEnforcing(pkt)
	mode := limits.ModeMonitor
	if enforcing {
		mode = limits.ModeEnforce
	}
	e.ledger.Record(limits.TableFlows, limits.ReasonRefused, mode)
	e.recordPacketStats(pkt, nil)
	e.recordLearnPacketLoss(pkt)
	if enforcing {
		return capture.Decision{Action: capture.Drop, Reason: "state_limit"}
	}
	if pkt.Token.Inline() {
		return observedDecision(pkt, acceptDecision)
	}
	return acceptDecision
}

func (e *Engine) mergeFlowSlotsLocked(a, b *flow.State) {
	if a.Admission == nil || b.Admission == nil {
		return
	}
	if a.Admission.Merge(b.Admission) {
		e.flowSlots -= 2
	}
	// Late NAT association can correct first-seen orientation. In particular,
	// datagram replies need not be the raw reverse tuple or use an ICS port.
	c := a.Connection.Load()
	for _, st := range []*flow.State{a, b} {
		st.Admission.Observe(st.Key.Proto, c.Direction(st.Key), false, false, false, 0, 0)
	}
}

func flowExpired(st *flow.State, now time.Time) bool {
	// Keep the configured idle timeout on the state itself: establishment can
	// change when its peer completes a handshake or a new incarnation starts.
	sample := *st
	if st.IdleTimeout == 30*time.Second && st.Admission != nil && st.Admission.Established() {
		sample.IdleTimeout = 5 * time.Minute
	}
	return sample.Expired(now)
}

// Consumers and workers must be joined before disposing configuration-owned
// traffic state. Stream teardown stays outside flowMu, as in idle expiry.
func (e *Engine) clearFlowOwners() {
	e.flowMu.Lock()
	states := make([]*flow.State, 0, len(e.flows))
	for index, st := range e.flows {
		if st != nil {
			states = append(states, e.dropFlowIndexLocked(index))
		}
	}
	records := e.observationPending
	e.observationPending = nil
	e.flowMu.Unlock()
	e.recordObservations(records)
	for _, st := range states {
		e.endFlowStream(st, nil)
	}
}
