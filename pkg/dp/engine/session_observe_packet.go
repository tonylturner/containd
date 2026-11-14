// SPDX-License-Identifier: Apache-2.0
package engine

import (
	"net/netip"
	"time"

	"github.com/tonylturner/containd/pkg/dp/capture"
	"github.com/tonylturner/containd/pkg/dp/dpi"
	"github.com/tonylturner/containd/pkg/dp/flow"
	"github.com/tonylturner/containd/pkg/dp/rules"
)

func (e *Engine) rawSessionOwnsConnection(pkt capture.Packet, incoming *flow.Connection) bool {
	t := e.sessions
	if t == nil {
		return false
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	state := wireServiceState(pkt)
	state.Connection.Store(incoming)
	src, a := addrPort(pkt.SrcIP, pkt.SrcPort)
	dst, b := addrPort(pkt.DstIP, pkt.DstPort)
	if a && b {
		if s, _ := t.lookupPacketLocked(src, dst, &state); s != nil {
			return s.mode == "enforce" || sessionProtocol(s.flow) == iecProtocol
		}
	}
	return sessionProtocol(&state) == iecProtocol && t.ownsStateLocked(pkt, &state)
}

func (e *Engine) endObservedSession(state *flow.State, remove bool) {
	t := e.sessions
	if t == nil {
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	c := state.Connection.Load()
	for key, s := range t.sessions {
		if s.mode != "monitor" || sessionProtocol(s.flow) == iecProtocol || s.flow == nil {
			continue
		}
		owned := s.flow.Connection.Load()
		if c == nil || owned == nil || c.Key != owned.Key {
			continue
		}
		t.stopParseLocked(s)
		if remove {
			t.deleteLocked(key, s)
		}
	}
}

func (e *Engine) bypassObservedSession(pkt capture.Packet, state *flow.State, stopped bool) bool {
	if sessionProtocol(state) == iecProtocol || pkt.Token.Inline() && e.enforcingPacketScope(pkt, state) {
		return false
	}
	parsed := dpi.ParsedPacket{Proto: pkt.Transport, SrcPort: pkt.SrcPort, DstPort: pkt.DstPort}
	if !stopped && e.ShouldInspect(state, &parsed) {
		return false
	}
	e.endObservedSession(state, false)
	e.recordPacketStats(pkt, state)
	noteCorrelationInspection(state, pkt, false)
	return true
}

// Passive generic capture can begin midstream. Its byte origin is only an
// observation boundary, never proof of a handshake or enforcing authority.
// IEC keeps its handshake-only observation profile.
func (t *sessionTable) observePickupLocked(client, server netip.AddrPort, ctx rules.EvalContext, pkt capture.Packet, state *flow.State, now time.Time) sessionResult {
	if t.fullLocked() {
		return accepted(reasonIECUntracked)
	}
	s := t.allocateSessionLocked(client, server, ctx, "monitor", state, now)
	if s == nil {
		return t.admissionLimitLocked("monitor")
	}
	s.state = sessionEstablished
	dir := sessionDirClient
	if state.ServiceKey().Dir == flow.DirReverse {
		dir = sessionDirSrv
	}
	t.sessions[sessionKey{client, server}] = s
	return t.livePacketLocked(s, dir, pkt, state, now)
}

func (t *sessionTable) resumeObservationLocked(s *trackedSession, dir int, pkt capture.Packet, now time.Time) *sessionResult {
	if s.mode != "monitor" || sessionProtocol(s.flow) == iecProtocol {
		return nil
	}
	if s.inspectionLost {
		// A budget refusal is terminal for this observation incarnation.
		// Resuming after pressure subsides would silently hide the lost range.
		return nil
	}
	if s.stopParse {
		// The old decoder, ranges and observe grants were retired together.
		// A later aligned packet may resume passive inspection, as before,
		// without borrowing any pre-loss pairing authority.
		s.dirs = [2]*sessionDir{}
		s.stopParse = false
	}
	if s.dirs[dir] == nil {
		if err := t.allocateDirLocked(s, dir, pkt.TCP.Seq-1); err != nil {
			res := t.inspectionLimitLocked(s, nil, now)
			return &res
		}
		s.dirs[dir].hasISN = false
	}
	return nil
}
