// SPDX-License-Identifier: Apache-2.0

package rules

import (
	"strings"
	"testing"
	"time"
)

func utc(y int, m time.Month, d, h, min, s int) time.Time {
	return time.Date(y, m, d, h, min, s, 0, time.UTC)
}

// TestScheduleCalendar is the calendar corpus: every instant is checked
// with ActiveAt, and through the evaluator for an ALLOW rule.
func TestScheduleCalendar(t *testing.T) {
	weekdays := []string{"Monday", "Tuesday", "Wednesday", "Thursday", "Friday"}
	for _, tc := range []struct {
		name   string
		sched  SchedulePredicate
		at     time.Time
		active bool
	}{
		// 2026-10-26 is a Monday.
		{"day window start is inclusive", SchedulePredicate{DaysOfWeek: weekdays, StartTime: "09:00", EndTime: "17:00"}, utc(2026, 10, 26, 9, 0, 0), true},
		{"day window before start", SchedulePredicate{DaysOfWeek: weekdays, StartTime: "09:00", EndTime: "17:00"}, utc(2026, 10, 26, 8, 59, 59), false},
		{"day window last instant", SchedulePredicate{DaysOfWeek: weekdays, StartTime: "09:00", EndTime: "17:00"}, utc(2026, 10, 26, 17, 0, 0).Add(-time.Nanosecond), true},
		{"end is exclusive", SchedulePredicate{DaysOfWeek: weekdays, StartTime: "09:00", EndTime: "17:00"}, utc(2026, 10, 26, 17, 0, 0), false},
		{"end minute is not included", SchedulePredicate{DaysOfWeek: weekdays, StartTime: "09:00", EndTime: "17:00"}, utc(2026, 10, 26, 17, 0, 30), false},
		{"unlisted day", SchedulePredicate{DaysOfWeek: weekdays, StartTime: "09:00", EndTime: "17:00"}, utc(2026, 10, 31, 10, 0, 0), false},

		{"overnight evening of its day", SchedulePredicate{DaysOfWeek: []string{"Monday"}, StartTime: "22:00", EndTime: "02:00"}, utc(2026, 10, 26, 23, 0, 0), true},
		{"overnight runs into the next day", SchedulePredicate{DaysOfWeek: []string{"Monday"}, StartTime: "22:00", EndTime: "02:00"}, utc(2026, 10, 27, 1, 59, 59), true},
		{"overnight end is exclusive", SchedulePredicate{DaysOfWeek: []string{"Monday"}, StartTime: "22:00", EndTime: "02:00"}, utc(2026, 10, 27, 2, 0, 0), false},
		{"overnight early morning of its own day is the previous day's window", SchedulePredicate{DaysOfWeek: []string{"Monday"}, StartTime: "22:00", EndTime: "02:00"}, utc(2026, 10, 26, 1, 0, 0), false},
		{"overnight evening of the next day", SchedulePredicate{DaysOfWeek: []string{"Monday"}, StartTime: "22:00", EndTime: "02:00"}, utc(2026, 10, 27, 22, 30, 0), false},

		{"week wrap Saturday into Sunday", SchedulePredicate{DaysOfWeek: []string{"Saturday"}, StartTime: "23:00", EndTime: "01:00"}, utc(2026, 11, 1, 0, 30, 0), true},
		{"week wrap Sunday into Monday", SchedulePredicate{DaysOfWeek: []string{"Sunday"}, StartTime: "23:00", EndTime: "01:00"}, utc(2026, 10, 26, 0, 30, 0), true},
		{"week wrap does not reach Monday night", SchedulePredicate{DaysOfWeek: []string{"Sunday"}, StartTime: "23:00", EndTime: "01:00"}, utc(2026, 10, 26, 23, 30, 0), false},

		{"day only covers the whole day", SchedulePredicate{DaysOfWeek: []string{"Monday"}}, utc(2026, 10, 27, 0, 0, 0).Add(-time.Nanosecond), true},
		{"day only ends at midnight", SchedulePredicate{DaysOfWeek: []string{"Monday"}}, utc(2026, 10, 27, 0, 0, 0), false},
		{"blank start is midnight", SchedulePredicate{EndTime: "06:00"}, utc(2026, 10, 26, 0, 0, 0), true},
		{"blank start ends at the end time", SchedulePredicate{EndTime: "06:00"}, utc(2026, 10, 26, 6, 0, 0), false},
		{"blank end runs to midnight", SchedulePredicate{StartTime: "22:00"}, utc(2026, 10, 26, 23, 59, 59), true},
		{"blank end does not run past midnight", SchedulePredicate{StartTime: "22:00"}, utc(2026, 10, 27, 0, 0, 0), false},
		{"end 00:00 runs to midnight", SchedulePredicate{StartTime: "22:00", EndTime: "00:00"}, utc(2026, 10, 26, 23, 59, 59), true},

		{"blank timezone is UTC, not the instant's zone", SchedulePredicate{StartTime: "09:00", EndTime: "17:00"},
			time.Date(2026, 10, 26, 16, 30, 0, 0, time.FixedZone("UTC-5", -5*3600)), false},
		{"blank timezone is UTC inside the window", SchedulePredicate{StartTime: "09:00", EndTime: "17:00"},
			time.Date(2026, 10, 26, 6, 30, 0, 0, time.FixedZone("UTC-5", -5*3600)), true},

		// 2026-03-08: New York skips 02:00-03:00 (07:00Z is 03:00 EDT).
		{"spring gap start resolves to the end of the gap", SchedulePredicate{DaysOfWeek: []string{"Sunday"}, StartTime: "02:30", EndTime: "04:00", Timezone: "America/New_York"}, utc(2026, 3, 8, 7, 0, 0), true},
		{"spring gap window does not open early", SchedulePredicate{DaysOfWeek: []string{"Sunday"}, StartTime: "02:30", EndTime: "04:00", Timezone: "America/New_York"}, utc(2026, 3, 8, 6, 59, 59), false},
		{"window inside the spring gap is empty", SchedulePredicate{DaysOfWeek: []string{"Sunday"}, StartTime: "02:00", EndTime: "02:30", Timezone: "America/New_York"}, utc(2026, 3, 8, 7, 0, 0), false},
		{"window across the spring gap is one real hour", SchedulePredicate{DaysOfWeek: []string{"Sunday"}, StartTime: "01:00", EndTime: "03:00", Timezone: "America/New_York"}, utc(2026, 3, 8, 7, 0, 0), false},
		// 2026-11-01: New York repeats 01:00-02:00 (05:00Z EDT, 06:00Z EST).
		{"fall fold start is the first occurrence", SchedulePredicate{DaysOfWeek: []string{"Sunday"}, StartTime: "01:30", EndTime: "02:00", Timezone: "America/New_York"}, utc(2026, 11, 1, 5, 30, 0), true},
		{"fall fold window spans the repeated hour", SchedulePredicate{DaysOfWeek: []string{"Sunday"}, StartTime: "01:30", EndTime: "02:00", Timezone: "America/New_York"}, utc(2026, 11, 1, 6, 30, 0), true},
		{"fall fold end is the first occurrence", SchedulePredicate{DaysOfWeek: []string{"Sunday"}, StartTime: "01:00", EndTime: "01:30", Timezone: "America/New_York"}, utc(2026, 11, 1, 6, 15, 0), false},
		{"fall day is 25 hours long", SchedulePredicate{DaysOfWeek: []string{"Sunday"}, Timezone: "America/New_York"}, utc(2026, 11, 2, 4, 59, 59), true},

		{"half-hour zone", SchedulePredicate{StartTime: "09:00", EndTime: "17:00", Timezone: "Asia/Kolkata"}, utc(2026, 10, 26, 3, 30, 0), true},
		{"half-hour zone before start", SchedulePredicate{StartTime: "09:00", EndTime: "17:00", Timezone: "Asia/Kolkata"}, utc(2026, 10, 26, 3, 29, 59), false},
		{"half-hour zone end", SchedulePredicate{StartTime: "09:00", EndTime: "17:00", Timezone: "Asia/Kolkata"}, utc(2026, 10, 26, 11, 30, 0), false},
		{"quarter-hour zone", SchedulePredicate{StartTime: "09:00", EndTime: "17:00", Timezone: "Asia/Kathmandu"}, utc(2026, 10, 26, 3, 15, 0), true},
		{"local weekday, not the UTC weekday", SchedulePredicate{DaysOfWeek: []string{"Tuesday"}, StartTime: "00:00", EndTime: "06:00", Timezone: "Asia/Kolkata"}, utc(2026, 10, 26, 19, 0, 0), true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := tc.sched.ActiveAt(tc.at)
			if err != nil || got != tc.active {
				t.Fatalf("ActiveAt(%s) = %v, %v; want %v", tc.at.UTC(), got, err, tc.active)
			}
			entry := Entry{ID: "s", Action: ActionAllow, Schedule: tc.sched}
			want := ActionDeny
			if tc.active {
				want = ActionAllow
			}
			if action := NewEvaluator(&Snapshot{Default: ActionDeny, Firewall: []Entry{entry}}).Evaluate(EvalContext{Now: tc.at}); action != want {
				t.Fatalf("Evaluate = %s, want %s", action, want)
			}
		})
	}
}

// TestScheduleWindows pins the absolute windows the kernel time sets are
// built from.
func TestScheduleWindows(t *testing.T) {
	for _, tc := range []struct {
		name     string
		sched    SchedulePredicate
		from, to time.Time
		want     []Window
	}{
		{"maintenance weekend across the fall change", SchedulePredicate{DaysOfWeek: []string{"Saturday", "Sunday"}, StartTime: "02:00", EndTime: "06:00", Timezone: "America/New_York"},
			utc(2026, 10, 30, 0, 0, 0), utc(2026, 11, 3, 0, 0, 0),
			[]Window{{utc(2026, 10, 31, 6, 0, 0), utc(2026, 10, 31, 10, 0, 0)}, {utc(2026, 11, 1, 7, 0, 0), utc(2026, 11, 1, 11, 0, 0)}}},
		{"spring gap window", SchedulePredicate{DaysOfWeek: []string{"Sunday"}, StartTime: "01:00", EndTime: "03:00", Timezone: "America/New_York"},
			utc(2026, 3, 7, 0, 0, 0), utc(2026, 3, 9, 0, 0, 0),
			[]Window{{utc(2026, 3, 8, 6, 0, 0), utc(2026, 3, 8, 7, 0, 0)}}},
		{"empty gap day yields no window", SchedulePredicate{DaysOfWeek: []string{"Sunday"}, StartTime: "02:00", EndTime: "02:30", Timezone: "America/New_York"},
			utc(2026, 3, 7, 0, 0, 0), utc(2026, 3, 9, 0, 0, 0), nil},
		{"overnight window that started before from", SchedulePredicate{StartTime: "22:00", EndTime: "02:00"},
			utc(2026, 10, 26, 1, 0, 0), utc(2026, 10, 26, 3, 0, 0),
			[]Window{{utc(2026, 10, 25, 22, 0, 0), utc(2026, 10, 26, 2, 0, 0)}}},
		{"whole days touch", SchedulePredicate{DaysOfWeek: []string{"Monday", "Tuesday"}},
			utc(2026, 10, 26, 0, 0, 0), utc(2026, 10, 28, 0, 0, 0),
			[]Window{{utc(2026, 10, 26, 0, 0, 0), utc(2026, 10, 27, 0, 0, 0)}, {utc(2026, 10, 27, 0, 0, 0), utc(2026, 10, 28, 0, 0, 0)}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := tc.sched.Windows(tc.from, tc.to)
			if err != nil {
				t.Fatal(err)
			}
			if len(got) != len(tc.want) {
				t.Fatalf("windows = %v, want %v", got, tc.want)
			}
			for i := range got {
				if !got[i].Start.Equal(tc.want[i].Start) || !got[i].End.Equal(tc.want[i].End) {
					t.Fatalf("windows = %v, want %v", got, tc.want)
				}
			}
		})
	}
	merged := MergeWindows([]Window{{utc(2026, 10, 26, 0, 0, 0), utc(2026, 10, 27, 0, 0, 0)}, {utc(2026, 10, 27, 0, 0, 0), utc(2026, 10, 28, 0, 0, 0)}})
	if len(merged) != 1 || !merged[0].End.Equal(utc(2026, 10, 28, 0, 0, 0)) {
		t.Fatalf("touching windows merge to %v", merged)
	}
}

func TestScheduleValidate(t *testing.T) {
	for _, tc := range []struct {
		sched SchedulePredicate
		err   string
	}{
		{SchedulePredicate{DaysOfWeek: []string{"Monday"}, StartTime: "09:00", EndTime: "17:00", Timezone: "America/New_York"}, ""},
		{SchedulePredicate{StartTime: "22:00", EndTime: "06:00"}, ""},
		{SchedulePredicate{StartTime: "22:00", EndTime: "00:00"}, ""},
		{SchedulePredicate{StartTime: "09:00", EndTime: "09:00"}, "distinct start and end"},
		{SchedulePredicate{EndTime: "00:00"}, "distinct start and end"},
		{SchedulePredicate{DaysOfWeek: []string{"monday"}}, `invalid day "monday"`},
		{SchedulePredicate{StartTime: "24:00"}, "startTime"},
		{SchedulePredicate{EndTime: "9:00"}, "endTime"},
		{SchedulePredicate{StartTime: "09:0a"}, "startTime"},
		{SchedulePredicate{Timezone: "Mars/Olympus"}, `timezone "Mars/Olympus"`},
	} {
		err := tc.sched.Validate()
		if (tc.err == "") != (err == nil) || (err != nil && !strings.Contains(err.Error(), tc.err)) {
			t.Errorf("Validate(%+v) = %v, want %q", tc.sched, err, tc.err)
		}
	}
}

func TestScheduleKeyEquivalence(t *testing.T) {
	a, errA := SchedulePredicate{StartTime: "00:00", EndTime: "06:00", Timezone: "UTC"}.ScheduleKey()
	b, errB := SchedulePredicate{EndTime: "06:00"}.ScheduleKey()
	c, errC := SchedulePredicate{EndTime: "06:00", Timezone: "America/New_York"}.ScheduleKey()
	if errA != nil || errB != nil || errC != nil || a != b || a == c {
		t.Fatalf("keys %q %q %q (%v %v %v): equivalent schedules must share a key, others must not", a, b, c, errA, errB, errC)
	}
}

// TestScheduleFailsClosed checks a schedule the engine cannot load: an
// ALLOW does not match and a DENY does.
func TestScheduleFailsClosed(t *testing.T) {
	bad := SchedulePredicate{StartTime: "09:00", EndTime: "17:00", Timezone: "Mars/Olympus"}
	ctx := EvalContext{Now: utc(2026, 10, 26, 10, 0, 0)}
	allow, deny := compileEntry(Entry{Action: ActionAllow, Schedule: bad}), compileEntry(Entry{Action: ActionDeny, Schedule: bad})
	if matchSchedule(&allow, ctx) {
		t.Fatal("an unloadable schedule admitted an ALLOW")
	}
	if !matchSchedule(&deny, ctx) {
		t.Fatal("an unloadable schedule lifted a DENY")
	}
}

// TestActiveAtMatchesWindows checks the window lookup the evaluator uses
// against the windows the nftables time sets are built from, every 15
// minutes over a year, across daylight-saving changes and overnight
// windows, and that it allocates nothing.
func TestActiveAtMatchesWindows(t *testing.T) {
	scheds := []SchedulePredicate{
		{DaysOfWeek: []string{"Monday", "Friday"}, StartTime: "22:00", EndTime: "06:00", Timezone: "America/New_York"},
		{StartTime: "01:30", EndTime: "03:00", Timezone: "Europe/Berlin"},
		{DaysOfWeek: []string{"Sunday"}, StartTime: "02:15", EndTime: "02:45", Timezone: "America/New_York"},
		{EndTime: "00:30", Timezone: "Australia/Lord_Howe"},
		{DaysOfWeek: []string{"Saturday"}},
	}
	for _, p := range scheds {
		s, err := parseSchedule(p)
		if err != nil {
			t.Fatal(err)
		}
		active := 0
		for at := utc(2026, 1, 1, 0, 0, 0); at.Before(utc(2027, 1, 1, 0, 0, 0)); at = at.Add(15 * time.Minute) {
			windows, err := p.Windows(at, at.Add(time.Nanosecond))
			if err != nil {
				t.Fatal(err)
			}
			if got := s.activeAt(at); got != (len(windows) > 0) {
				t.Fatalf("%+v at %s: activeAt = %v, Windows = %v", p, at, got, windows)
			}
			if len(windows) > 0 {
				active++
			}
		}
		if active == 0 {
			t.Fatalf("%+v is never active: the comparison proves nothing", p)
		}
	}
	ce := compileEntry(Entry{Action: ActionAllow, Schedule: scheds[0]})
	ctx := EvalContext{Now: utc(2026, 10, 27, 3, 30, 0)}
	if allocs := testing.AllocsPerRun(100, func() { matchSchedule(&ce, ctx) }); allocs != 0 {
		t.Fatalf("matchSchedule allocates %v times per call", allocs)
	}
}
