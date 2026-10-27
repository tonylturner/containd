// SPDX-License-Identifier: Apache-2.0

package config

import (
	"fmt"

	"github.com/tonylturner/containd/pkg/dp/rules"
)

// validateSchedule checks a rule schedule against the calendar the
// dataplane enforces (see rules.SchedulePredicate).
func validateSchedule(s *ScheduleConfig, ruleID string) error {
	if s == nil {
		return nil
	}
	if err := s.Predicate().Validate(); err != nil {
		return fmt.Errorf("rule %s schedule: %w", ruleID, err)
	}
	return nil
}

// Predicate is the dataplane form of a rule schedule; nil has no window.
func (s *ScheduleConfig) Predicate() rules.SchedulePredicate {
	if s == nil {
		return rules.SchedulePredicate{}
	}
	return rules.SchedulePredicate{
		DaysOfWeek: append([]string(nil), s.DaysOfWeek...),
		StartTime:  s.StartTime,
		EndTime:    s.EndTime,
		Timezone:   s.Timezone,
	}
}
