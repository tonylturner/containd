// SPDX-License-Identifier: Apache-2.0

package coverage

// SummaryState is the overall ICS protection of a rule set: one of the rule
// states, or SummaryNone / SummaryUnknown.
type SummaryState string

const (
	// SummaryNone: no firewall rule names an ICS protocol.
	SummaryNone SummaryState = "none"
	// SummaryUnknown: the engine could not be asked.
	SummaryUnknown SummaryState = "unknown"
)

// Summary counts rules by state. It names no rule and no exclusion, so it
// is safe to publish without authentication.
type Summary struct {
	State        SummaryState `json:"state"`
	Enforcing    int          `json:"enforcing"`
	Partial      int          `json:"partial"`
	NotEnforcing int          `json:"notEnforcing"`
	Monitoring   int          `json:"monitoring"`
}

// Summarize counts rs. The state is the worst state among enforce-mode
// rules, monitoring when every rule is in monitor mode, and none without
// rules.
func Summarize(rs []Rule) Summary {
	var s Summary
	for _, r := range rs {
		switch r.State {
		case Enforcing:
			s.Enforcing++
		case Partial:
			s.Partial++
		case NotEnforcing:
			s.NotEnforcing++
		case Monitoring:
			s.Monitoring++
		}
	}
	switch {
	case s.NotEnforcing > 0:
		s.State = SummaryState(NotEnforcing)
	case s.Partial > 0:
		s.State = SummaryState(Partial)
	case s.Enforcing > 0:
		s.State = SummaryState(Enforcing)
	case s.Monitoring > 0:
		s.State = SummaryState(Monitoring)
	default:
		s.State = SummaryNone
	}
	return s
}
