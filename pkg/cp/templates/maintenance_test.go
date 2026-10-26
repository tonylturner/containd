// SPDX-License-Identifier: Apache-2.0

package templates

import (
	"testing"
	"time"
)

// TestMaintenanceTemplateWindow pins the template's window under the
// enforced calendar: weekend mornings 02:00-06:00 New York time, in UTC
// across the daylight-saving change.
func TestMaintenanceTemplateWindow(t *testing.T) {
	for _, r := range maintenanceRules() {
		sched := r.Schedule.Predicate()
		if err := sched.Validate(); err != nil {
			t.Fatalf("rule %s: %v", r.ID, err)
		}
		for _, tc := range []struct {
			at     time.Time
			active bool
		}{
			{time.Date(2026, 10, 31, 6, 0, 0, 0, time.UTC), true},  // Saturday 02:00 EDT
			{time.Date(2026, 10, 31, 10, 0, 0, 0, time.UTC), false}, // Saturday 06:00 EDT
			{time.Date(2026, 11, 1, 6, 30, 0, 0, time.UTC), false},  // Sunday 01:30 EST
			{time.Date(2026, 11, 1, 7, 0, 0, 0, time.UTC), true},    // Sunday 02:00 EST
			{time.Date(2026, 11, 2, 7, 0, 0, 0, time.UTC), false},   // Monday
		} {
			if got, err := sched.ActiveAt(tc.at); err != nil || got != tc.active {
				t.Errorf("rule %s at %s: active %v, %v; want %v", r.ID, tc.at, got, err, tc.active)
			}
		}
	}
}
