// SPDX-License-Identifier: Apache-2.0

package engine

import "github.com/tonylturner/containd/pkg/common/metrics"

// Snapshot diffs preserve counters across reconfiguration and avoid counting
// offline work. Gauge deltas also support multiple independently owned engines.
func (live *liveObserver) syncMetrics() {
	next, prev := live.observer.Counters(), live.last
	for p, name := range []string{"modbus", "dnp3", "iec104", "cip", "unknown"} {
		for s, outcome := range []string{"confirmed", "reject", "incomplete"} {
			metrics.IdentificationOutcomes.WithLabelValues(name, outcome).Add(float64(next.Outcomes[p][s] - prev.Outcomes[p][s]))
		}
	}
	for i, reason := range []string{"budget", "timeout", "conflict", "midstream", "truncated", "closed"} {
		metrics.IdentificationIncomplete.WithLabelValues(reason).Add(float64(next.Incomplete[i] - prev.Incomplete[i]))
	}
	metrics.IdentificationRefusals.Add(float64(next.Refusals - prev.Refusals))
	metrics.IdentificationEntries.Add(float64(next.Entries - prev.Entries))
	metrics.IdentificationBytes.Add(float64(next.ChargedBytes - prev.ChargedBytes))
	metrics.IdentificationMarkers.Add(float64(next.Markers - prev.Markers))
	metrics.IdentificationBindings.Add(float64(next.Bindings - prev.Bindings))
	live.last = next
}
