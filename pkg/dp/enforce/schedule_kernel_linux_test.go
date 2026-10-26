// SPDX-License-Identifier: Apache-2.0
//go:build linux

package enforce

import (
	"testing"
	"time"

	"github.com/tonylturner/containd/pkg/dp/rules"
)

// TestScheduledAllowKernelAdmitsNothing forwards real packets between two
// zones. nftables cannot evaluate a schedule, so a scheduled ALLOW must not
// admit traffic at any time; the same rule without its schedule does.
func TestScheduledAllowKernelAdmitsNothing(t *testing.T) {
	lab := newNetnsLab(t, "sch", 30, 30*time.Second)
	lab.run(t, "ip", "-n", lab.client, "route", "add", "198.18.40.0/24", "via", "198.18.30.1")
	lab.run(t, "ip", "-n", lab.target, "route", "add", "198.18.30.0/24", "via", "198.18.40.1")
	lab.serveTarget(t, "198.18.40.2", 18001)
	// Every day, all day: the window always holds, so only the kernel's
	// inability to evaluate it can keep the rule from admitting traffic.
	always := rules.SchedulePredicate{
		DaysOfWeek: []string{"Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday", "Sunday"},
		StartTime:  "00:00", EndTime: "23:59",
	}
	for _, tc := range []struct {
		name     string
		schedule rules.SchedulePredicate
		admitted bool
	}{
		{"scheduled", always, false},
		{"unscheduled", rules.SchedulePredicate{}, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			snap := &rules.Snapshot{
				Default:    rules.ActionDeny,
				ZoneIfaces: map[string][]string{"l3": {"sch0"}, "l1": {"sch1"}},
				Firewall: []rules.Entry{{ID: "maint", SourceZones: []string{"l3"}, DestZones: []string{"l1"},
					Protocols: []rules.Protocol{{Name: "tcp", Port: "18001"}}, Action: rules.ActionAllow, Schedule: tc.schedule}},
			}
			lab.apply(t, NewCompiler(), snap)
			err := lab.probe("198.18.40.2", 18001, "198.18.30.2")
			if tc.admitted && err != nil {
				t.Fatalf("unscheduled ALLOW did not admit: %v", err)
			}
			if !tc.admitted && err == nil {
				t.Fatal("scheduled ALLOW admitted traffic")
			}
		})
	}
}
