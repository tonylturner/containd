// SPDX-License-Identifier: Apache-2.0

package engine

import (
	"fmt"
	"time"

	"github.com/tonylturner/containd/pkg/dp/anomaly"
	"github.com/tonylturner/containd/pkg/dp/capture"
	"github.com/tonylturner/containd/pkg/dp/conntrack"
	"github.com/tonylturner/containd/pkg/dp/dpi"
	"github.com/tonylturner/containd/pkg/dp/flow"
	"github.com/tonylturner/containd/pkg/dp/identify"
)

// Seeing a wire SYN is not proof that its requests reached correlation.
// Deliberate inspection bypasses extend the same bounded recovery window as
// dropped observations, without changing exclusions or wire policy inputs.
func noteCorrelationInspection(state *flow.State, pkt capture.Packet, inspected bool) {
	c := state.Connection.Load()
	if c == nil {
		return
	}
	if !inspected {
		c.LoseCorrelation(pkt.Timestamp, anomaly.ModbusPairingTimeout)
		return
	}
	if pkt.Proto == 6 && pkt.TCP.Valid && pkt.TCP.Flags&capture.TCPFlagSYN != 0 && pkt.TCP.Flags&capture.TCPFlagACK == 0 {
		c.Coverage().Store(true)
	}
}

func (e *Engine) handleTransportPacket(pkt capture.Packet, c *flow.Connection, history *transportAdmission) {
	defer func() {
		if r := recover(); r != nil {
			e.reportPacketPanic(packetPanic(r))
		}
	}()
	e.handlePacketConnection(pkt, c, history)
}

// Caller holds flowMu. Both possible wire orientations are searched; CT peer
// association does not rewrite the flow's key or require a service-port hint.
func (e *Engine) tupleStateLocked(tuple conntrack.Tuple) *flow.State {
	for _, dir := range []flow.Direction{flow.DirForward, flow.DirReverse} {
		if st := e.flows[flow.TupleMapKey(tuple, dir)]; st != nil {
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
// streams before their tuple can be reused, except when the IEC table owns
// their lifecycle. Inline admission remains unchanged.
func (e *Engine) retireTransportIncarnation(pkt capture.Packet, incoming *flow.Connection) {
	if pkt.Token.Inline() {
		return
	}
	state := wireServiceState(pkt)
	state.Connection.Store(incoming)
	iecOwned := e.iecOwnsState(pkt, state)
	e.flowMu.Lock()
	retired := e.retireTransportIncarnationLocked(pkt, incoming, iecOwned)
	e.flowMu.Unlock()
	for _, old := range retired {
		e.endFlowStream(old, nil)
	}
}

// Caller holds flowMu; IEC ownership is queried before acquiring it.
func (e *Engine) retireTransportIncarnationLocked(pkt capture.Packet, incoming *flow.Connection, iecOwned bool) []*flow.State {
	if pkt.Token.Inline() {
		return nil
	}
	st := e.tupleStateLocked(packetKey(pkt).Tuple())
	var retired []*flow.State
	if st != nil {
		old := st.Connection.Load()
		newSYN := pkt.Proto == 6 && pkt.TCP.Valid && pkt.TCP.Flags&capture.TCPFlagSYN != 0 &&
			pkt.TCP.Flags&capture.TCPFlagACK == 0
		if isn, ok := e.transportISNs[st.Key.MapKey()]; ok && isn == pkt.TCP.Seq {
			newSYN = false
		}
		var evidence *conntrack.Evidence
		if old != nil {
			evidence = old.Evidence
		}
		if iecOwned && e.transport != nil {
			e.transport.admissionMu.Lock()
			if marker := e.transportCoverage[st].root(); marker != nil && marker.generation != nil {
				evidence = marker.generation
			}
			e.transport.admissionMu.Unlock()
		}
		if iecOwned && e.observation != nil && old != nil {
			if ctx := e.observation.entries[identify.Key(old.Key)]; ctx != nil {
				evidence = ctx.generation
			}
		}
		newGeneration := incoming != nil && incoming.Verified() && evidence != nil &&
			!sameGeneration(evidence, incoming.Evidence)
		if iecOwned {
			// The table owns legacy flow/session retirement. Only recycle the
			// passive incarnation marker; never end its directional streams,
			// close correlation or replace its flow state.
			if newSYN || newGeneration {
				e.retireDecodeCoverageLocked(st, incoming)
				e.retireObservationLocked(st, incoming)
				e.noteTransportSYNLocked(pkt, st.Key)
			}
		} else if newSYN || newGeneration || old != nil && old.Closed().Load() {
			peer := st.Key.Reversed()
			if old != nil {
				peer = old.Peer(st.Key)
			}
			for _, candidate := range []*flow.State{st, e.tupleStateLocked(peer.Tuple())} {
				if candidate != nil && e.flows[candidate.Key.MapKey()] == candidate {
					retired = append(retired, e.dropFlowLocked(candidate.Key))
				}
			}
		}
	}
	return retired
}

// The healthy path checks incarnation retirement under the flow-tracking lock
// it already needs. A real retirement still ends streams before creating the
// replacement state, preserving peer lookup and close ordering.
func (e *Engine) trackTransportFlow(pkt capture.Packet, now time.Time, incoming *flow.Connection) *flow.State {
	hint := wireServiceState(pkt)
	hint.Connection.Store(incoming)
	iecOwned := !pkt.Token.Inline() && e.iecOwnsState(pkt, hint)
	e.flowMu.Lock()
	retired := e.retireTransportIncarnationLocked(pkt, incoming, iecOwned)
	if len(retired) != 0 {
		e.flowMu.Unlock()
		for _, old := range retired {
			e.endFlowStream(old, nil)
		}
		e.flowMu.Lock()
	}
	state, forgotten, needsSweep := e.trackFlowLocked(pkt, now)
	e.flowMu.Unlock()
	e.finishFlowTracking(forgotten, needsSweep, now)
	return state
}

// A retained IEC session owns its tuple even if its current envelope changes.
// Otherwise ownership is decided from the same opener-oriented envelope as
// the table's new-session path. Call before taking flowMu.
func (e *Engine) iecOwnsPacket(pkt capture.Packet) bool {
	state := wireServiceState(pkt)
	e.flowMu.Lock()
	if retained := e.tupleStateLocked(state.Key.Tuple()); retained != nil {
		state.Connection.Store(retained.Connection.Load())
	}
	e.flowMu.Unlock()
	return e.iecOwnsState(pkt, state)
}

func (e *Engine) iecOwnsState(pkt capture.Packet, state *flow.State) bool {
	t := e.iec
	if t == nil {
		return false
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	if !t.hasIEC {
		return false
	}
	src, srcOK := addrPort(pkt.SrcIP, pkt.SrcPort)
	dst, dstOK := addrPort(pkt.DstIP, pkt.DstPort)
	if !isIECFlow(state) {
		if srcOK && dstOK {
			session, _ := t.lookupLocked(src, dst)
			return session != nil
		}
		return false
	}
	if !srcOK || !dstOK {
		// Non-IPv4 traffic is table-owned only inside an enforce
		// envelope. This query has no actions or session mutations.
		_, owned := t.nonIPv4Locked(state)
		return owned
	}
	if session, _ := t.lookupLocked(src, dst); session != nil {
		return true
	}
	matched, _ := t.envelopeLocked(t.stateContext(state))
	return matched
}

func (e *Engine) noteTransportSYNLocked(pkt capture.Packet, key flow.Key) {
	if !pkt.Token.Inline() && pkt.Proto == 6 && pkt.TCP.Valid &&
		pkt.TCP.Flags&capture.TCPFlagSYN != 0 && pkt.TCP.Flags&capture.TCPFlagACK == 0 {
		if e.transportISNs == nil {
			e.transportISNs = make(map[flow.MapKey]uint32)
		}
		e.transportISNs[key.MapKey()] = pkt.TCP.Seq
	}
}

func (e *Engine) newWireConnectionLocked(status string) *flow.Connection {
	e.wireSerial++
	c := &flow.Connection{Key: fmt.Sprintf("wire/%p/%d", e, e.wireSerial), Status: status}
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
			old = e.newWireConnectionLocked("wire")
		}
		state.Connection.Store(old)
		return
	}
	// The existing original history owns the incarnation key. A history
	// without a public ID may acquire evidence; an issued ID is never renamed.
	if incoming.Evidence != nil {
		selected := false
		for _, issued := range []bool{true, false} {
			for _, tuple := range []conntrack.Tuple{incoming.Evidence.Original, incoming.Evidence.Reply} {
				if history := e.tupleStateLocked(tuple); history != nil {
					previous := history.Connection.Load()
					if previous != nil && !previous.Closed().Load() &&
						(previous.ID != "") == issued &&
						(previous.Evidence == nil || sameGeneration(previous.Evidence, incoming.Evidence)) {
						incoming = adoptTransport(previous, incoming)
						selected = true
						break
					}
				}
			}
			if selected {
				break
			}
		}
	} else if old != nil {
		incoming = adoptTransport(old, incoming)
	} else if peer := e.tupleStateLocked(state.Key.Reversed().Tuple()); peer != nil {
		if previous := peer.Connection.Load(); previous != nil && !previous.Closed().Load() {
			incoming = adoptTransport(previous, incoming)
		}
	}
	if old != nil && old.ID != "" && incoming.ID != old.ID {
		incoming = adoptTransport(old, &flow.Connection{Status: "ambiguous"})
		if e.transport != nil {
			e.transport.authority.count("ambiguous")
		}
	}
	e.adoptTransportPending(incoming, old)
	state.Connection.Store(incoming)
	state.Tags = e.flowTags(state)
	if incoming.Evidence != nil {
		for _, tuple := range []conntrack.Tuple{incoming.Evidence.Original, incoming.Evidence.Reply} {
			if peer := e.tupleStateLocked(tuple); peer != nil {
				previous := peer.Connection.Load()
				e.adoptTransportPending(incoming, previous)
				if previous == nil || previous.ID == "" || previous.ID == incoming.ID {
					peer.Connection.Store(incoming)
					peer.Tags = e.flowTags(peer)
				}
			}
		}
	}
}

func (e *Engine) adoptTransportPending(incoming, previous *flow.Connection) {
	if incoming.Evidence != nil && previous != nil && previous.ID == "" && previous.Key != incoming.Key {
		e.adoptObservationLocked(incoming, previous)
		incoming.MergeHistory(previous)
		if e.anomalyDetector != nil {
			e.anomalyDetector.AdoptConnection(previous.Key, incoming)
		}
	}
}

func adoptTransport(previous, incoming *flow.Connection) *flow.Connection {
	id := previous.ID
	if id == "" {
		id = incoming.ID
	}
	evidence := incoming.Evidence
	if evidence == nil {
		evidence = previous.Evidence
	}
	if previous.ID == id && previous.Status == incoming.Status && previous.Evidence == evidence {
		previous.MergeHistory(incoming)
		return previous
	}
	fresh := &flow.Connection{ID: id, Key: previous.Key, Status: incoming.Status, Evidence: evidence}
	fresh.InheritLifecycle(previous)
	fresh.MergeHistory(incoming)
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
		e.finishObservation(state)
		c.Closed().Store(true)
		if e.transport != nil {
			e.transport.retireAdmission(state)
		}
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
