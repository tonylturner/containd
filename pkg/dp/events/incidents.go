// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 containd Authors

package events

import "github.com/tonylturner/containd/pkg/dp/ics/eventfields"

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
	for _, key := range []string{eventfields.KeyAPDUID, eventfields.KeyTriggerAPDUID} {
		if v, _ := eventfields.String(evidence.Attributes, key); v == apdu {
			return true
		}
	}
	// Both live []string and JSON-decoded []any shapes occur in telemetry.
	switch ids := evidence.Attributes[eventfields.KeyAPDUIDs].(type) {
	case []string:
		for _, id := range ids {
			if id == apdu {
				return true
			}
		}
	case []any:
		for _, id := range ids {
			if id == apdu {
				return true
			}
		}
	}
	return false
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
	for i := range s.general.events {
		candidate := s.general.at(i)
		if sessionKey(candidate) == sessionKey(ev) && implicated(candidate, ev) {
			s.pushIncident(r, candidate)
		}
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
