// SPDX-License-Identifier: Apache-2.0
package engine

// Both indexes refer only to the table's current incarnations. Token history
// is bounded by 64 slots per tuple and shares their reserved metadata credit;
// held residency associations remain independently owned by settlements.
func (t *sessionTable) publishSessionLocked(key sessionKey, s *trackedSession) {
	if old := t.sessions[key]; old != nil {
		t.unindexSessionLocked(old)
	}
	t.sessions[key] = s
	if s.flow != nil {
		if c := s.flow.Connection.Load(); c != nil && c.Key != "" {
			t.byConnection[c.Key] = s
			s.connectionKey = c.Key
		}
	}
}

func (t *sessionTable) unindexSessionLocked(s *trackedSession) {
	for _, tok := range s.tokens {
		if t.tokenOwners[tok].session == s {
			delete(t.tokenOwners, tok)
		}
	}
	if t.byConnection[s.connectionKey] == s {
		delete(t.byConnection, s.connectionKey)
	}
	s.connectionKey = ""
}
