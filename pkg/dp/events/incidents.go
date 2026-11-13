// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 containd Authors

package events

import (
	"iter"

	"github.com/tonylturner/containd/pkg/dp/ics/eventfields"
)

const (
	incidentCapacity = 128
	incidentRows     = 32
)

// incidentBank protects bounded session bundles independently of routine traffic.
// Whole oldest bundles are evicted at 128 sessions; within a bundle the oldest
// row is evicted at 32 rows. Context is limited to implicated APDUs, not all
// allowed objects from an incident's session. Callers hold the store mutex.
type incidentBank struct {
	groups map[string]*eventRing
	order  []string
}

func incidentEvidence(ev Event) bool {
	if ev.Proto != eventfields.ProtoIEC104 {
		return false
	}
	switch ev.Kind {
	case eventfields.KindDecision:
		return ev.Attributes[eventfields.KeyDecision] == "deny" || ev.Attributes[eventfields.KeyDecision] == "would_drop"
	case eventfields.KindVerdict:
		return true // dropped as well as drop_failed: enforcement outcome, not delivery proof
	case eventfields.KindSession:
		switch ev.Attributes[eventfields.KeyOutcome] {
		case "aborted", "reset_sent", "reset_failed", "enforce_unhealthy":
			return true
		}
	}
	return false
}

func sessionKey(ev Event) string {
	id, _ := eventfields.String(ev.Attributes, eventfields.KeySessionID)
	return id
}

func implicated(context, evidence Event) bool {
	apdu, _ := eventfields.String(context.Attributes, eventfields.KeyAPDUID)
	if apdu == "" {
		return false
	}
	for id := range incidentAPDUIDs(evidence) {
		if id == apdu {
			return true
		}
	}
	return false
}

func incidentAPDUIDs(evidence Event) iter.Seq[string] {
	return func(yield func(string) bool) {
		for _, key := range []string{eventfields.KeyAPDUID, eventfields.KeyTriggerAPDUID} {
			if id, _ := eventfields.String(evidence.Attributes, key); id != "" && !yield(id) {
				return
			}
		}
		// Both live []string and JSON-decoded []any shapes occur in telemetry.
		switch ids := evidence.Attributes[eventfields.KeyAPDUIDs].(type) {
		case []string:
			for _, id := range ids {
				if id != "" && !yield(id) {
					return
				}
			}
		case []any:
			for _, value := range ids {
				if id, ok := value.(string); ok && id != "" && !yield(id) {
					return
				}
			}
		}
	}
}

func (s *Store) retainIncident(ev Event) {
	if ev.Proto != eventfields.ProtoIEC104 {
		return
	}
	key := sessionKey(ev)
	critical := incidentEvidence(ev)
	if key == "" {
		if !critical {
			return
		}
		key = "@health" // bounded singleton for sessionless enforcement health
	}
	b := &s.incidents
	r := b.groups[key]
	if !critical {
		if r == nil {
			return
		}
		for _, evidence := range r.events {
			if incidentEvidence(evidence) && implicated(ev, evidence) {
				s.pushIncident(r, ev)
				return
			}
		}
		return
	}
	if r == nil {
		if b.groups == nil {
			b.groups = make(map[string]*eventRing)
		}
		if len(b.order) == incidentCapacity {
			delete(b.groups, b.order[0])
			b.order = b.order[1:]
			s.historyTruncated = true
		}
		r = &eventRing{capacity: incidentRows}
		b.groups[key] = r
		b.order = append(b.order, key)
	}
	// Capture already-recorded decoded attempts. The reverse insertion order
	// (decision before decoded events) is handled by the noncritical path above.
	for _, i := range s.incidentContext.matches(s.general, ev) {
		s.pushIncident(r, s.general.at(i))
	}
	s.pushIncident(r, ev)
}

func (s *Store) pushIncident(r *eventRing, ev Event) {
	for _, old := range r.events {
		if old.ID == ev.ID {
			return
		}
	}
	if _, overflow := r.push(ev); overflow {
		s.historyTruncated = true
	}
}
