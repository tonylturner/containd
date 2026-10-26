// SPDX-License-Identifier: Apache-2.0

package capture

import (
	"sync"

	"github.com/tonylturner/containd/pkg/dp/events"
	"github.com/tonylturner/containd/pkg/dp/flow"
)

// ruleHit is one event a recordingSink received.
type ruleHit struct {
	ev  events.Event
	key *flow.Key
}

// recordingSink records the rule hits it receives.
type recordingSink struct {
	mu   sync.Mutex
	hits []ruleHit
}

func (s *recordingSink) RuleHit(ev events.Event, key *flow.Key) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.hits = append(s.hits, ruleHit{ev: ev, key: key})
}

func (s *recordingSink) recorded() []ruleHit {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]ruleHit(nil), s.hits...)
}
