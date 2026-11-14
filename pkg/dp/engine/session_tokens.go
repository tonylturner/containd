// SPDX-License-Identifier: Apache-2.0
package engine

import "github.com/tonylturner/containd/pkg/dp/capture"

// A bounded history, not a success-waiting map: immediate Repeat normally has
// no successful completion. Held credits keep their association until residency
// is proven settled, independently of this rolling history.
type sessionToken struct {
	token   capture.Token
	verdict capture.Verdict
}

func (t *sessionTable) rememberTokenLocked(s *trackedSession, tok capture.Token, v capture.Verdict) {
	if !tok.Inline() {
		return
	}
	if c := t.settlements[tok]; c != nil {
		c.session, c.verdict = s, v
	}
	for i := range s.tokens {
		if s.tokens[i].token == tok {
			s.tokens[i].verdict = v
			return
		}
	}
	s.tokens[s.tokenNext] = sessionToken{tok, v}
	s.tokenNext = (s.tokenNext + 1) % len(s.tokens)
}

func (t *sessionTable) tokenOwnerLocked(tok capture.Token) (*trackedSession, capture.Verdict) {
	if c := t.settlements[tok]; c != nil && c.session != nil {
		return c.session, c.verdict
	}
	for _, s := range t.sessions {
		for _, w := range s.tokens {
			if w.token == tok {
				return s, w.verdict
			}
		}
	}
	return nil, 0
}
