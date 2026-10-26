// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

package services

import (
	"slices"
	"testing"
	"time"
)

// meterBase is the start of a minute, so base.Add(n*time.Minute) is minute n.
var meterBase = time.Date(2026, 10, 26, 9, 0, 0, 0, time.UTC)

func atMinute(n int) time.Time {
	return meterBase.Add(time.Duration(n)*time.Minute + 30*time.Second)
}

func TestMeterSnapshotZeroFillsQuietMinutes(t *testing.T) {
	t.Parallel()

	var m meter
	m.add(atMinute(0), 2)
	m.add(atMinute(0), 1)
	m.add(atMinute(3), 1)

	cases := []struct {
		name string
		now  int
		want []int
		rate float64
	}{
		{"gap between events", 3, []int{3, 0, 0, 1}, 1},
		{"quiet minutes through now", 5, []int{3, 0, 0, 1, 0, 0}, 4.0 / 6},
		{"window slides past the first event", 7, []int{0, 0, 1, 0, 0, 0, 0}, 1.0 / 7},
		{"no events in the window", 30, []int{0, 0, 0, 0, 0, 0, 0}, 0},
	}
	for _, tc := range cases {
		series, total, rate := m.snapshot(atMinute(tc.now))
		if !slices.Equal(series, tc.want) || total != 4 || rate != tc.rate {
			t.Errorf("%s: snapshot = %v, %d, %v; want %v, 4, %v", tc.name, series, total, rate, tc.want, tc.rate)
		}
	}
}

func TestMeterKeepsOnlyTheWindow(t *testing.T) {
	t.Parallel()

	var m meter
	for minute := range 10 {
		m.add(atMinute(minute), minute+1)
	}
	if len(m.buckets) != meterWindow {
		t.Fatalf("retained %d buckets, want %d", len(m.buckets), meterWindow)
	}
	series, total, rate := m.snapshot(atMinute(9))
	if want := []int{4, 5, 6, 7, 8, 9, 10}; !slices.Equal(series, want) {
		t.Fatalf("series = %v, want %v", series, want)
	}
	if total != 55 || rate != 7 {
		t.Fatalf("total, rate = %d, %v; want 55, 7", total, rate)
	}
}

func TestMeterOrdersMinutesWhenTheClockStepsBack(t *testing.T) {
	t.Parallel()

	var m meter
	m.add(atMinute(2), 1)
	m.add(atMinute(0), 2)
	m.add(atMinute(2), 1)
	m.add(atMinute(1), 4)
	// A current time before the newest event still ends at that event.
	series, total, _ := m.snapshot(atMinute(1))
	if want := []int{2, 4, 2}; !slices.Equal(series, want) || total != 8 {
		t.Fatalf("snapshot = %v, %d; want %v, 8", series, total, want)
	}
}

func TestMeterSnapshotIsEmptyBeforeAnyEvent(t *testing.T) {
	t.Parallel()

	for name, m := range map[string]*meter{"nil": nil, "unused": {}} {
		series, total, rate := m.snapshot(atMinute(0))
		if series == nil || len(series) != 0 || total != 0 || rate != 0 {
			t.Errorf("%s meter snapshot = %#v, %d, %v; want empty series", name, series, total, rate)
		}
	}
}

func TestMeterStatusAlignsErrorSeriesToNow(t *testing.T) {
	t.Parallel()

	var primary, errs meter
	primary.add(atMinute(0), 5)
	errs.add(atMinute(2), 1)
	status := meterStatusAt(atMinute(4), &primary, &errs)
	if got, want := status["sparkline"].([]int), []int{5, 0, 0, 0, 0}; !slices.Equal(got, want) {
		t.Fatalf("sparkline = %v, want %v", got, want)
	}
	if got, want := status["errors_sparkline"].([]int), []int{1, 0, 0}; !slices.Equal(got, want) {
		t.Fatalf("errors_sparkline = %v, want %v", got, want)
	}
	if status["count"] != 5 || status["errors_count"] != 1 {
		t.Fatalf("counts = %v, %v; want 5, 1", status["count"], status["errors_count"])
	}
	if status["rate_per_min"] != 1.0 || status["errors_rate_per_min"] != 1.0/3 {
		t.Fatalf("rates = %v, %v; want 1, 1/3", status["rate_per_min"], status["errors_rate_per_min"])
	}
}
