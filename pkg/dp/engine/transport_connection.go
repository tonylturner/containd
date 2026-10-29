// SPDX-License-Identifier: Apache-2.0

package engine

import (
	"fmt"

	"github.com/tonylturner/containd/pkg/dp/capture"
	"github.com/tonylturner/containd/pkg/dp/conntrack"
	"github.com/tonylturner/containd/pkg/dp/dpi"
	"github.com/tonylturner/containd/pkg/dp/flow"
)

func (e *Engine) handleTransportPacket(pkt capture.Packet, c *flow.Connection, loss uint64) {
	defer func() {
		if r := recover(); r != nil {
			e.reportPacketPanic(packetPanic(r))
		}
	}()
	if c.LossEpoch != loss {
		c.Coverage().Store(false)
	}
	e.handlePacketConnection(pkt, c)
}

// Caller holds flowMu. Both possible wire orientations are searched; CT peer
// association does not rewrite the flow's key or require a service-port hint.
func (e *Engine) tupleStateLocked(tuple conntrack.Tuple) *flow.State {
	for _, dir := range []flow.Direction{flow.DirForward, flow.DirReverse} {
		if st := e.flows[flow.TupleKey(tuple, dir).Hash()]; st != nil {
			return st
		}
	}
	return nil
}

func (e *Engine) peerFlow(state *flow.State) *flow.State {
	key := state.Key.Reversed()
	if c := state.Connection.Load(); c != nil {
		key = c.Peer(state.Key)
	}
	e.flowMu.Lock()
	defer e.flowMu.Unlock()
	return e.tupleStateLocked(key.Tuple())
}

// A fresh raw SYN or verified kernel generation retires both directional
// streams before their tuple can be reused. Inline admission remains unchanged.
func (e *Engine) retireTransportIncarnation(pkt capture.Packet, incoming *flow.Connection) {
	if pkt.Token.Inline() || isIECPort(pkt) {
		return
	}
	e.flowMu.Lock()
	st := e.tupleStateLocked(packetKey(pkt).Tuple())
	var retired []*flow.State
	if st != nil {
		old := st.Connection.Load()
		newSYN := pkt.Proto == 6 && pkt.TCP.Valid && pkt.TCP.Flags&capture.TCPFlagSYN != 0 &&
			pkt.TCP.Flags&capture.TCPFlagACK == 0
		if isn, ok := e.transportISNs[st.Key.Hash()]; ok && isn == pkt.TCP.Seq {
			newSYN = false
		}
		newGeneration := incoming != nil && incoming.Verified() && old != nil && old.Evidence != nil &&
			!sameGeneration(old.Evidence, incoming.Evidence)
		if newSYN || newGeneration || old != nil && old.Closed().Load() {
			peer := st.Key.Reversed()
			if old != nil {
				peer = old.Peer(st.Key)
			}
			for _, candidate := range []*flow.State{st, e.tupleStateLocked(peer.Tuple())} {
				if candidate != nil && e.flows[candidate.Key.Hash()] == candidate {
					retired = append(retired, e.dropFlowLocked(candidate.Key))
				}
			}
		}
	}
	e.flowMu.Unlock()
	for _, old := range retired {
		e.endFlowStream(old, nil)
	}
}

func (e *Engine) noteTransportSYNLocked(pkt capture.Packet, key flow.Key) {
	if !pkt.Token.Inline() && pkt.Proto == 6 && pkt.TCP.Valid &&
		pkt.TCP.Flags&capture.TCPFlagSYN != 0 && pkt.TCP.Flags&capture.TCPFlagACK == 0 {
		if e.transportISNs == nil {
			e.transportISNs = make(map[string]uint32)
		}
		e.transportISNs[key.Hash()] = pkt.TCP.Seq
	}
}

func (e *Engine) newWireConnectionLocked(status string) *flow.Connection {
	e.wireSerial++
	c := &flow.Connection{Key: fmt.Sprintf("wire/%p/%d", e, e.wireSerial), Status: status}
	c.Coverage().Store(status == "offline")
	return c
}

func (e *Engine) bindTransport(state *flow.State, incoming *flow.Connection) {
	e.flowMu.Lock()
	defer e.flowMu.Unlock()
	old := state.Connection.Load()
	if incoming == nil {
		if old != nil {
			return
		}
		if peer := e.tupleStateLocked(state.Key.Reversed().Tuple()); peer != nil {
			old = peer.Connection.Load()
		}
		if old == nil {
			old = e.newWireConnectionLocked("offline")
		}
		state.Connection.Store(old)
		return
	}
	if incoming.Verified() {
		// Prefer the existing original-direction history. Never merge an
		// already-published unresolved request into a new CT identity.
		history := e.tupleStateLocked(incoming.Evidence.Original)
		if history == nil || history.Connection.Load() == nil || !history.Connection.Load().Published().Load() {
			history = e.tupleStateLocked(incoming.Evidence.Reply)
		}
		if history != nil {
			if previous := history.Connection.Load(); previous != nil && previous.Published().Load() {
				if previous.Evidence == nil {
					if e.transport != nil {
						e.transport.authority.count("identity_frozen")
					}
					if old == nil {
						old = e.newWireConnectionLocked("identity_frozen")
					}
					state.Connection.Store(old)
					return
				}
				if sameGeneration(previous.Evidence, incoming.Evidence) && !previous.Closed().Load() {
					incoming = revalidateTransport(previous, incoming)
				}
			}
		}
		if old != nil && old.Published().Load() && old.Evidence == nil {
			return
		}
		// A reply-only history also freezes its ID. A periodic authority
		// refresh must not rename it just because O has not been observed.
		if old != nil && old.Published().Load() && sameGeneration(old.Evidence, incoming.Evidence) && !old.Closed().Load() {
			incoming = revalidateTransport(old, incoming)
		}
	} else if old != nil {
		// Keep the private incarnation while evidence is unavailable. CT
		// IDs are exposed only when the authority generation is current.
		if old.Evidence != nil {
			status := incoming.ResolutionStatus()
			old.Unavailable.Store(&status)
			old.Gap().Store(true)
			old.Coverage().Store(false)
			return
		}
		if old.Published().Load() {
			fresh := &flow.Connection{Key: old.Key, Status: incoming.ResolutionStatus(), LossEpoch: old.LossEpoch}
			fresh.InheritLifecycle(old)
			state.Connection.Store(fresh)
			return
		}
		incoming = &flow.Connection{Key: old.Key, Status: incoming.Status, LossEpoch: incoming.LossEpoch}
		incoming.InheritLifecycle(old)
	}
	if !incoming.Verified() {
		if peer := e.tupleStateLocked(state.Key.Reversed().Tuple()); peer != nil {
			if p := peer.Connection.Load(); p != nil && p.Evidence == nil && !p.Closed().Load() {
				incoming = &flow.Connection{Key: p.Key, Status: incoming.ResolutionStatus(), LossEpoch: incoming.LossEpoch}
				incoming.InheritLifecycle(p)
			}
		}
	}
	state.Connection.Store(incoming)
	if incoming.Verified() {
		for _, tuple := range []conntrack.Tuple{incoming.Evidence.Original, incoming.Evidence.Reply} {
			if peer := e.tupleStateLocked(tuple); peer != nil {
				if previous := peer.Connection.Load(); previous != nil && previous.Key == incoming.Key {
					peer.Connection.Store(incoming)
				}
			}
		}
	}
}

func revalidateTransport(previous, incoming *flow.Connection) *flow.Connection {
	if previous.Verified() {
		return previous
	}
	fresh := &flow.Connection{ID: previous.ID, Key: previous.Key, Status: "resolved",
		Evidence: incoming.Evidence, Authority: incoming.Authority, AuthorityVersion: incoming.AuthorityVersion,
		LossEpoch: previous.LossEpoch, AuthorityLoss: previous.AuthorityLoss}
	fresh.InheritLifecycle(previous)
	fresh.Gap().Store(previous.Gap().Load() || previous.AuthorityLoss != incoming.AuthorityLoss)
	return fresh
}

func (e *Engine) closeCorrelation(state *flow.State, reset, expired bool) {
	c := state.Connection.Load()
	if c == nil {
		return
	}
	mask := uint32(1) << c.Direction(state.Key)
	for {
		old := c.FIN().Load()
		if c.FIN().CompareAndSwap(old, old|mask) {
			break
		}
	}
	if reset || expired || c.FIN().Load() == 3 {
		c.Closed().Store(true)
		if e.anomalyDetector != nil {
			e.anomalyDetector.ForgetConnection(c.Key)
		}
	}
}

func bindEventConnections(state *flow.State, evs []dpi.Event) {
	if state == nil {
		return
	}
	c := state.Connection.Load()
	for i := range evs {
		if evs[i].Connection == nil {
			evs[i].Connection = c
		}
		if c := evs[i].Connection; c != nil {
			evs[i].TransportConnectionID = c.PublicID()
			evs[i].CorrelationStatus = c.ResolutionStatus()
		}
	}
	if c != nil && len(evs) != 0 {
		c.Published().Store(true)
	}
}
