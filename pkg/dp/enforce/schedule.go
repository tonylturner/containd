// SPDX-License-Identifier: Apache-2.0

package enforce

import (
	"bytes"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/tonylturner/containd/pkg/dp/rules"
)

// Schedules compile to interval sets of absolute times in the policy table,
// matched with "meta time": the kernel opens and closes each window itself,
// at the planned instants, without userspace. The sets cover a bounded
// horizon, [ScheduleFrom, ScheduleFrom+ScheduleHorizon); the engine's
// planner refills them before the horizon runs out (ScheduleRefresh).
//
// A set fails closed beyond its horizon, and before it after a clock step
// back: an ALLOW set holds only the planned windows, so a scheduled ALLOW
// stops matching, and a DENY or RESET set also holds all time outside the
// horizon, so a scheduled DENY keeps applying.
//
// Window boundaries are whole seconds. nft intervals are closed, so a window
// [start, end) is written start-end and also matches the single nanosecond
// at its end; touching windows are merged first.

// DefaultScheduleHorizon is the horizon when Compiler.ScheduleHorizon is 0.
const DefaultScheduleHorizon = 24 * time.Hour

// scheduleTimeMax is the last second a meta time value (nanoseconds in 64
// bits, as Go's UnixNano) can hold.
const scheduleTimeMax = 9223372036

// scheduleSet is one schedule time set: the windows of a calendar for rules
// of one polarity.
type scheduleSet struct {
	name  string
	sched rules.SchedulePredicate
	deny  bool // DENY and RESET: all time outside the horizon is included
}

// scheduleSetOf returns the time set of a scheduled entry. Rules with the
// same calendar and polarity share it.
func scheduleSetOf(e rules.Entry) (scheduleSet, error) {
	key, err := e.Schedule.ScheduleKey()
	if err != nil {
		return scheduleSet{}, fmt.Errorf("entry %s schedule: %w", e.ID, err)
	}
	set := scheduleSet{name: "schedule_allow_" + key, sched: e.Schedule}
	if e.Action != rules.ActionAllow {
		set = scheduleSet{name: "schedule_deny_" + key, sched: e.Schedule, deny: true}
	}
	return set, nil
}

// ScheduleHorizonLength is the length of c's schedule horizon.
func (c *Compiler) ScheduleHorizonLength() time.Duration {
	if c.ScheduleHorizon <= 0 {
		return DefaultScheduleHorizon
	}
	return c.ScheduleHorizon
}

// horizon returns c's schedule horizon in whole seconds.
func (c *Compiler) horizon() (from, to time.Time) {
	from = c.ScheduleFrom
	if from.IsZero() {
		from = time.Now()
	}
	from = from.Truncate(time.Second)
	return from, from.Add(c.ScheduleHorizonLength()).Truncate(time.Second)
}

// elements returns the set's intervals for the horizon [from, to).
func (s scheduleSet) elements(from, to time.Time) ([]string, error) {
	windows, err := s.sched.Windows(from, to)
	if err != nil {
		return nil, err
	}
	if s.deny {
		windows = append(windows, rules.Window{Start: time.Unix(0, 0), End: from}, rules.Window{Start: to, End: time.Unix(scheduleTimeMax, 0)})
	} else {
		for i := range windows {
			if windows[i].End.After(to) {
				windows[i].End = to
			}
		}
	}
	slices.SortFunc(windows, func(a, b rules.Window) int { return a.Start.Compare(b.Start) })
	var out []string
	for _, w := range rules.MergeWindows(windows) {
		out = append(out, fmt.Sprintf("%d-%d", w.Start.Unix(), w.End.Unix()))
	}
	return out, nil
}

func (s scheduleSet) write(buf *bytes.Buffer, from, to time.Time) error {
	elems, err := s.elements(from, to)
	if err != nil {
		return err
	}
	fmt.Fprintf(buf, "  set %s {\n    typeof meta time;\n    flags interval;\n", s.name)
	if len(elems) > 0 {
		fmt.Fprintf(buf, "    elements = { %s }\n", strings.Join(elems, ", "))
	}
	buf.WriteString("  }\n")
	return nil
}

// ScheduleRefresh returns the transaction that refills the schedule time
// sets of a ruleset installed for snap with c's horizon, or "" when snap
// compiles to none. Each set is flushed and refilled in the same
// transaction, so no packet sees a set between its old and new windows.
func (c *Compiler) ScheduleRefresh(snap *rules.Snapshot) (string, error) {
	p, err := newPredicates(snap, c.QueueID)
	if err != nil {
		return "", err
	}
	from, to := c.horizon()
	table := c.policyTable()
	var b strings.Builder
	for _, set := range p.scheduleSets() {
		elems, err := set.elements(from, to)
		if err != nil {
			return "", err
		}
		fmt.Fprintf(&b, "flush set inet %s %s\n", table, set.name)
		if len(elems) > 0 {
			fmt.Fprintf(&b, "add element inet %s %s { %s }\n", table, set.name, strings.Join(elems, ", "))
		}
	}
	return b.String(), nil
}
