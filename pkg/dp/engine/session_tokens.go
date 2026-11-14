// SPDX-License-Identifier: Apache-2.0
package engine

import "github.com/tonylturner/containd/pkg/dp/capture"

// A bounded history, not a success-waiting map: immediate Repeat normally has
// no successful completion. Held credits keep their association until residency
// is proven settled, independently of this rolling history.
type sessionToken struct {
	session *trackedSession
	verdict capture.Verdict
}

func (t *sessionTable) rememberTokenLocked(s *trackedSession, tok capture.Token, v capture.Verdict) {
	if !tok.Inline() {
		return
	}
	if c := t.settlements[tok]; c != nil {
		c.session, c.verdict = s, v
	}
	if owner := t.tokenOwners[tok]; owner.session == s {
		t.tokenOwners[tok] = sessionToken{s, v}
		return
	}
	old := s.tokens[s.tokenNext]
	if t.tokenOwners[old].session == s {
		delete(t.tokenOwners, old)
	}
	s.tokens[s.tokenNext] = tok
	s.tokenNext = (s.tokenNext + 1) % len(s.tokens)
	t.tokenOwners[tok] = sessionToken{s, v}
}

func (t *sessionTable) tokenOwnerLocked(tok capture.Token) (*trackedSession, capture.Verdict) {
	if c := t.settlements[tok]; c != nil && c.session != nil {
		return c.session, c.verdict
	}
	owner := t.tokenOwners[tok]
	return owner.session, owner.verdict
}
