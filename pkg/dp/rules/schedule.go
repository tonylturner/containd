// SPDX-License-Identifier: Apache-2.0

package rules

import (
	"encoding/hex"
	"fmt"
	"sync"
	"time"
	// Zone data ships with every binary that evaluates schedules, so a host
	// or image without zoneinfo files still loads IANA timezones.
	_ "time/tzdata"
)

// This file is the one calendar of recurring rule schedules. The userspace
// evaluator, the nftables time sets and the rule preview all derive their
// windows from it:
//
//   - A window opens on each listed day, or on every day when none is
//     listed, at the start time in the schedule's timezone. It closes at the
//     end time, which is exclusive.
//   - A window whose end time is not after its start time is an overnight
//     window: it ends on the next day. It belongs to the day it starts on.
//   - A blank start time is 00:00 and a blank end time is the end of the day.
//     Equal start and end times are invalid.
//   - A blank timezone is UTC.
//   - A local time that a daylight-saving change skips is the instant the
//     gap ends. A local time that occurs twice is its first occurrence.

// Window is the absolute interval [Start, End) of one schedule window.
type Window struct {
	Start, End time.Time
}

const minutesPerDay = 24 * 60

// schedule is a parsed SchedulePredicate.
type schedule struct {
	days  uint8 // bit per time.Weekday
	start int   // minutes after local midnight of the window's day
	end   int   // minutes after the same midnight; after start, at most a day later
	loc   *time.Location
}

var scheduleDays = map[string]time.Weekday{
	"Sunday": time.Sunday, "Monday": time.Monday, "Tuesday": time.Tuesday, "Wednesday": time.Wednesday,
	"Thursday": time.Thursday, "Friday": time.Friday, "Saturday": time.Saturday,
}

// Validate reports whether p is a valid schedule: known day names, HH:MM
// times, distinct start and end times and a loadable IANA timezone.
func (p SchedulePredicate) Validate() error {
	_, err := parseSchedule(p)
	return err
}

// ActiveAt reports whether a window of p holds at t.
func (p SchedulePredicate) ActiveAt(t time.Time) (bool, error) {
	s, err := parseSchedule(p)
	if err != nil {
		return false, err
	}
	return s.activeAt(t), nil
}

// Windows returns the windows of p that intersect [from, to), in order. They
// never overlap; consecutive windows can touch.
func (p SchedulePredicate) Windows(from, to time.Time) ([]Window, error) {
	s, err := parseSchedule(p)
	if err != nil || !from.Before(to) {
		return nil, err
	}
	// An overnight window that starts the day before from can still hold.
	first := civilDate(from.In(s.loc)).AddDate(0, 0, -1)
	last := civilDate(to.In(s.loc))
	var out []Window
	for day := first; !day.After(last); day = day.AddDate(0, 0, 1) {
		w, ok := s.windowOn(day)
		if ok && w.Start.Before(to) && w.End.After(from) {
			out = append(out, w)
		}
	}
	return out, nil
}

// MergeWindows joins touching and overlapping windows of an ordered list.
func MergeWindows(windows []Window) []Window {
	var out []Window
	for _, w := range windows {
		if n := len(out); n > 0 && !w.Start.After(out[n-1].End) {
			if w.End.After(out[n-1].End) {
				out[n-1].End = w.End
			}
			continue
		}
		out = append(out, w)
	}
	return out
}

// ScheduleKey identifies the calendar of p: equivalent schedules, such as a
// blank and a 00:00 start or a blank and a UTC timezone, have the same key.
// It is made of lowercase hex digits, decimal digits and underscores.
func (p SchedulePredicate) ScheduleKey() (string, error) {
	s, err := parseSchedule(p)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("%02x_%04d_%04d_%s", s.days, s.start, s.end, hex.EncodeToString([]byte(s.loc.String()))), nil
}

// Location returns the timezone of p: UTC when blank.
func (p SchedulePredicate) Location() (*time.Location, error) {
	return loadLocation(p.Timezone)
}

func parseSchedule(p SchedulePredicate) (schedule, error) {
	s := schedule{start: 0, end: minutesPerDay}
	for _, d := range p.DaysOfWeek {
		wd, ok := scheduleDays[d]
		if !ok {
			return schedule{}, fmt.Errorf("invalid day %q", d)
		}
		s.days |= 1 << uint(wd)
	}
	if s.days == 0 {
		s.days = 0x7f
	}
	if p.StartTime != "" {
		m, err := parseHHMM(p.StartTime)
		if err != nil {
			return schedule{}, fmt.Errorf("startTime: %w", err)
		}
		s.start = m
	}
	if p.EndTime != "" {
		m, err := parseHHMM(p.EndTime)
		if err != nil {
			return schedule{}, fmt.Errorf("endTime: %w", err)
		}
		if m == s.start {
			return schedule{}, fmt.Errorf("endTime %s equals the start time; a window needs distinct start and end times", p.EndTime)
		}
		if m < s.start {
			m += minutesPerDay
		}
		s.end = m
	}
	loc, err := loadLocation(p.Timezone)
	if err != nil {
		return schedule{}, err
	}
	s.loc = loc
	return s, nil
}

// parseHHMM returns the minutes after midnight of a 24-hour "HH:MM" time.
func parseHHMM(v string) (int, error) {
	digit := func(i int) int { return int(v[i] - '0') }
	if len(v) != 5 || v[2] != ':' {
		return 0, fmt.Errorf("invalid time %q, expected HH:MM", v)
	}
	for _, i := range []int{0, 1, 3, 4} {
		if v[i] < '0' || v[i] > '9' {
			return 0, fmt.Errorf("invalid time %q, expected HH:MM", v)
		}
	}
	h, m := digit(0)*10+digit(1), digit(3)*10+digit(4)
	if h > 23 || m > 59 {
		return 0, fmt.Errorf("invalid time %q, expected HH:MM from 00:00 to 23:59", v)
	}
	return h*60 + m, nil
}

// windowOn returns the window that opens on a calendar day, if any. day is
// a civil date: midnight UTC.
func (s schedule) windowOn(day time.Time) (Window, bool) {
	if s.days&(1<<uint(day.Weekday())) == 0 {
		return Window{}, false
	}
	start := resolveWall(day.Add(time.Duration(s.start)*time.Minute), s.loc)
	end := resolveWall(day.Add(time.Duration(s.end)*time.Minute), s.loc)
	// Both ends inside one daylight-saving gap leave nothing.
	if !end.After(start) {
		return Window{}, false
	}
	return Window{Start: start, End: end}, true
}

// civilDate is the calendar date of t as midnight UTC.
func civilDate(t time.Time) time.Time {
	return time.Date(t.Year(), t.Month(), t.Day(), 0, 0, 0, 0, time.UTC)
}

// wallOf is the local wall clock of t as a UTC time.
func wallOf(t time.Time) time.Time {
	return time.Date(t.Year(), t.Month(), t.Day(), t.Hour(), t.Minute(), t.Second(), 0, time.UTC)
}

// resolveWall returns the instant a wall clock time (given as a UTC time)
// names in loc: its first occurrence, or the end of the gap that skips it.
// time.Date does not define which instant it picks in either case.
func resolveWall(wall time.Time, loc *time.Location) time.Time {
	t := time.Date(wall.Year(), wall.Month(), wall.Day(), wall.Hour(), wall.Minute(), 0, 0, loc)
	start, end := t.ZoneBounds()
	if !wallOf(t).Equal(wall) {
		// A gap: t lies in the zone before or after it.
		if wallOf(t).After(wall) {
			return start
		}
		return end
	}
	if start.IsZero() {
		return t
	}
	// The wall time can also occur in the preceding zone, earlier.
	_, offset := start.Add(-time.Nanosecond).Zone()
	if earlier := wall.Add(-time.Duration(offset) * time.Second).In(loc); earlier.Before(start) && wallOf(earlier).Equal(wall) {
		return earlier
	}
	return t
}

// locations caches loaded timezones: the evaluator resolves them per packet.
var locations sync.Map // name -> *time.Location

// loadLocation loads an IANA timezone; blank is UTC.
func loadLocation(name string) (*time.Location, error) {
	if name == "" {
		return time.UTC, nil
	}
	if loc, ok := locations.Load(name); ok {
		return loc.(*time.Location), nil
	}
	loc, err := time.LoadLocation(name)
	if err != nil {
		return nil, fmt.Errorf("timezone %q: %w", name, err)
	}
	locations.Store(name, loc)
	return loc, nil
}

func schedulePredicateEmpty(s SchedulePredicate) bool {
	return len(s.DaysOfWeek) == 0 && s.StartTime == "" && s.EndTime == ""
}

// compiledSchedule is an entry's schedule predicate parsed once per
// snapshot. A predicate that does not parse is invalid.
type compiledSchedule struct {
	set     bool // the entry has a schedule predicate
	invalid bool
	s       schedule
}

func compileSchedule(entry Entry) compiledSchedule {
	if !entry.HasSchedulePredicate() {
		return compiledSchedule{}
	}
	s, err := parseSchedule(entry.Schedule)
	return compiledSchedule{set: true, invalid: err != nil, s: s}
}

// activeAt reports whether a window of s holds at t, as Windows does for
// [t, t+1ns), without building the windows: only the windows that open on
// t's local day or the day before can hold.
func (s schedule) activeAt(t time.Time) bool {
	day := civilDate(t.In(s.loc))
	for _, d := range [2]time.Time{day.AddDate(0, 0, -1), day} {
		if w, ok := s.windowOn(d); ok && !t.Before(w.Start) && w.End.After(t) {
			return true
		}
	}
	return false
}

// matchSchedule matches an entry's compiled schedule at the context's time
// (now when unset). A schedule that cannot be evaluated fails closed: an
// ALLOW does not match, and a DENY or RESET does.
func matchSchedule(ce *compiledEntry, ctx EvalContext) bool {
	if !ce.schedule.set {
		return true
	}
	if ce.schedule.invalid {
		return ce.Action == ActionDeny || ce.Action == ActionReset
	}
	now := ctx.Now
	if now.IsZero() {
		now = time.Now()
	}
	return ce.schedule.s.activeAt(now)
}
