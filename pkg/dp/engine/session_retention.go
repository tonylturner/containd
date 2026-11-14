// SPDX-License-Identifier: Apache-2.0
package engine

import "time"

func (t *sessionTable) retainDenialLocked(s *trackedSession, now time.Time) sessionActions {
	if s.state == sessionAborted {
		return sessionActions{}
	}
	s.state, s.endedAt = sessionAborted, now
	t.tombstones++
	if s.genericDenial() {
		s.denialOrder = t.denials.PushBack(s)
	}
	return t.evictTombstoneLocked()
}

// Generic denial protection has the same fixed lifetime and FIFO capacity as
// the generic inline path. The session itself is the tombstone; no parallel
// registry can retire its stream or reset work independently.
func (s *trackedSession) genericDenial() bool {
	if s.flow != nil {
		proto := sessionProtocol(s.flow)
		return proto == "modbus" || proto == "dnp3"
	}
	return s.server.Port() == 502 || s.server.Port() == 20000
}

func (s *trackedSession) denialExpired(now time.Time) bool {
	ttl := sessionTombstoneTTL
	if s.genericDenial() {
		ttl = deniedTCPLifetime
	}
	return !now.Before(s.endedAt.Add(ttl))
}

func (t *sessionTable) removeDenialLocked(s *trackedSession) {
	if s.denialOrder != nil {
		t.denials.Remove(s.denialOrder)
		s.denialOrder = nil
	}
}

func (t *sessionTable) fullLocked() bool {
	// Generic tombstones have their own fixed bound. They must not exhaust
	// live session admission long before reaching that retention bound.
	return len(t.sessions)-t.denials.Len() >= sessionMaxSessions
}
