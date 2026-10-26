// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

package events

import "sort"

const denyCapacity = 1024

func (s *Store) appendEvent(ev Event) {
	if isDeny(ev) {
		if _, overflow := s.denies.push(ev); overflow {
			s.historyTruncated = true
		}
	}
	s.retainIncident(ev)
	s.appendGeneral(ev)
}

func isDeny(ev Event) bool {
	return ev.Kind == "firewall.rule.hit" && ev.Attributes["action"] == "DENY"
}

// ListTelemetry includes the independent DENY and IEC incident banks. General-store consumers
// (List, Flows, MatchingEvents and TimeRange) deliberately do not see that bank.
// Each bank has independent overflow; no age expiry or persistence applies.
func (s *Store) ListTelemetry(limit int) []Event {
	if s == nil {
		return nil
	}
	s.mu.Lock()
	candidates := make([]Event, 0, len(s.general.events)+len(s.denies.events))
	candidates = append(candidates, s.general.events...)
	candidates = append(candidates, s.denies.events...)
	for _, group := range s.incidents.groups {
		candidates = append(candidates, group.events...)
	}
	s.mu.Unlock()
	return SelectTelemetry(candidates, limit)
}

// SelectTelemetry chooses a bounded, deduplicated evidence-aware page, then
// orders that page newest-first. DENYs take slots before ordinary telemetry;
// an engine-unreachable error always gets a slot, even when limit is one.
// This shared selection must also run after management merges service events.
// A nonpositive limit selects all candidates.
func SelectTelemetry(candidates []Event, limit int) []Event {
	ranked := append([]Event(nil), candidates...)
	sort.SliceStable(ranked, func(i, j int) bool {
		pi, pj := telemetryPriority(ranked[i]), telemetryPriority(ranked[j])
		if pi != pj {
			return pi < pj
		}
		return newer(ranked[i], ranked[j])
	})
	if limit <= 0 || limit > len(ranked) {
		limit = len(ranked)
	}
	out := make([]Event, 0, limit)
	seen := make(map[uint64]bool, len(ranked))
	for _, ev := range ranked {
		if len(out) == limit {
			break
		}
		if seen[ev.ID] {
			continue
		}
		seen[ev.ID] = true
		out = append(out, ev)
	}
	sort.SliceStable(out, func(i, j int) bool { return newer(out[i], out[j]) })
	return out
}

func telemetryPriority(ev Event) int {
	if ev.Kind == "system.engine.telemetry_error" {
		return 0
	}
	if isDeny(ev) || incidentEvidence(ev) {
		return 1
	}
	return 2
}

func newer(a, b Event) bool {
	if a.Timestamp.Equal(b.Timestamp) {
		return a.ID > b.ID
	}
	return a.Timestamp.After(b.Timestamp)
}
