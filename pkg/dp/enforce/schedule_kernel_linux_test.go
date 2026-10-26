// SPDX-License-Identifier: Apache-2.0
//go:build linux

package enforce

import (
	"testing"
	"time"

	"github.com/tonylturner/containd/pkg/dp/rules"
)

// TestScheduleKernelWindows forwards real connections between two zones
// under scheduled rules: the kernel's time sets admit a scheduled ALLOW only
// inside its window and apply a scheduled DENY only inside its window, and
// past the planned horizon the ALLOW stops and the DENY applies.
func TestScheduleKernelWindows(t *testing.T) {
	lab := newNetnsLab(t, "sch", 30, 60*time.Second)
	lab.run(t, "ip", "-n", lab.client, "route", "add", "198.18.40.0/24", "via", "198.18.30.1")
	lab.run(t, "ip", "-n", lab.target, "route", "add", "198.18.30.0/24", "via", "198.18.40.1")
	lab.serveTarget(t, "198.18.40.2", 18001)
	now := time.Now().UTC()
	everyDay := rules.SchedulePredicate{DaysOfWeek: []string{"Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday", "Sunday"}}
	notToday := rules.SchedulePredicate{DaysOfWeek: []string{now.AddDate(0, 0, 3).Weekday().String()}}
	snap := func(action rules.Action, sched rules.SchedulePredicate) *rules.Snapshot {
		def := rules.ActionDeny
		if action == rules.ActionDeny {
			def = rules.ActionAllow
		}
		return &rules.Snapshot{
			Default:    def,
			ZoneIfaces: map[string][]string{"l3": {"sch0"}, "l1": {"sch1"}},
			Firewall: []rules.Entry{{ID: "maint", SourceZones: []string{"l3"}, DestZones: []string{"l1"},
				Protocols: []rules.Protocol{{Name: "tcp", Port: "18001"}}, Action: action, Schedule: sched}},
		}
	}
	for _, tc := range []struct {
		name     string
		action   rules.Action
		sched    rules.SchedulePredicate
		from     time.Time // horizon start; zero is now
		admitted bool
	}{
		{"allow in window", rules.ActionAllow, everyDay, time.Time{}, true},
		{"allow outside window", rules.ActionAllow, notToday, time.Time{}, false},
		{"allow past its horizon", rules.ActionAllow, everyDay, now.Add(-2 * time.Hour), false},
		{"deny in window", rules.ActionDeny, everyDay, time.Time{}, false},
		{"deny outside window", rules.ActionDeny, notToday, time.Time{}, true},
		{"deny past its horizon", rules.ActionDeny, notToday, now.Add(-2 * time.Hour), false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := NewCompiler()
			c.ScheduleFrom = tc.from
			if !tc.from.IsZero() {
				c.ScheduleHorizon = time.Hour
			}
			lab.apply(t, c, snap(tc.action, tc.sched))
			err := lab.probe("198.18.40.2", 18001, "198.18.30.2")
			if tc.admitted && err != nil {
				t.Fatalf("connection refused: %v", err)
			}
			if !tc.admitted && err == nil {
				t.Fatal("connection admitted")
			}
		})
	}
}
