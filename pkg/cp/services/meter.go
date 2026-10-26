// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

package services

import (
	"slices"
	"time"
)

// meterWindow is the number of one-minute buckets a meter reports.
const meterWindow = 7

type sparkBucket struct {
	minute int64
	count  int
}

// meter counts events in one-minute buckets for sparkline and rate telemetry.
// It is not safe for concurrent use; owners guard it with their own lock.
type meter struct {
	total int
	// buckets holds the minutes that recorded events, ascending, within
	// meterWindow minutes of the newest one.
	buckets []sparkBucket
}

func unixMinute(t time.Time) int64 {
	return t.UTC().Unix() / 60
}

func (m *meter) add(now time.Time, delta int) {
	if delta == 0 {
		return
	}
	m.total += delta
	minute := unixMinute(now)
	// A wall clock stepped backwards records into an earlier minute.
	i := len(m.buckets)
	for i > 0 && m.buckets[i-1].minute > minute {
		i--
	}
	if i > 0 && m.buckets[i-1].minute == minute {
		m.buckets[i-1].count += delta
	} else {
		m.buckets = slices.Insert(m.buckets, i, sparkBucket{minute: minute, count: delta})
	}
	oldest := m.buckets[len(m.buckets)-1].minute - meterWindow + 1
	keep := 0
	for keep < len(m.buckets) && m.buckets[keep].minute < oldest {
		keep++
	}
	m.buckets = m.buckets[keep:]
}

func (m *meter) active() bool {
	return m != nil && (m.total != 0 || len(m.buckets) > 0)
}

// snapshot returns the per-minute series, the lifetime total and the average
// per-minute rate across the series. The series has one entry per minute,
// oldest first, through the current minute: minutes without events are
// zeros. It starts at the meter's first event when that is less than
// meterWindow minutes ago and is empty before any event.
func (m *meter) snapshot(now time.Time) (series []int, total int, ratePerMin float64) {
	if m == nil || len(m.buckets) == 0 {
		return []int{}, 0, 0
	}
	end := max(unixMinute(now), m.buckets[len(m.buckets)-1].minute)
	start := max(m.buckets[0].minute, end-meterWindow+1)
	series = make([]int, end-start+1)
	windowTotal := 0
	for _, b := range m.buckets {
		if b.minute < start {
			continue
		}
		series[b.minute-start] = b.count
		windowTotal += b.count
	}
	return series, m.total, float64(windowTotal) / float64(len(series))
}

// meterStatus renders primary and error meters with the service status keys.
func meterStatus(primary, errs *meter) map[string]any {
	return meterStatusAt(time.Now(), primary, errs)
}

// meterStatusAt renders both meters through the minute of now, so their
// series end at the same minute.
func meterStatusAt(now time.Time, primary, errs *meter) map[string]any {
	spark, count, rate := primary.snapshot(now)
	errSpark, errCount, errRate := errs.snapshot(now)
	return map[string]any{
		"sparkline":           spark,
		"count":               count,
		"rate_per_min":        rate,
		"errors_sparkline":    errSpark,
		"errors_count":        errCount,
		"errors_rate_per_min": errRate,
	}
}
