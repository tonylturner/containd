// SPDX-License-Identifier: Apache-2.0
package engine

import "github.com/tonylturner/containd/pkg/dp/flow"

// Coordinates are resolved by bindTransport before entering the session lock.
// The existing table remains the only owner; connection keys locate histories,
// not a second alias registry. Verdict I/O follows the caller's flow unlock.
func (t *sessionTable) retireMergedHistory(survivor, losing *flow.Connection) sessionActions {
	var acts sessionActions
	if survivor == nil || losing == nil || survivor.Key == losing.Key {
		return acts
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	now := t.now()
	for key, s := range t.sessions {
		if s.flow == nil {
			continue
		}
		c := s.flow.Connection.Load()
		if c == nil || c.Key != losing.Key {
			continue
		}
		if s.state == sessionAborted || s.state == sessionClosed {
			continue
		}
		if s.mode == "enforce" {
			acts.merge(t.abortLocked(s, abortTransport, "", nil, now))
		} else {
			acts.merge(t.deleteLocked(key, s))
			t.dpi.EndStream(s.id)
		}
	}
	return acts
}
