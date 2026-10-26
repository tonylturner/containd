// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

package services

import "time"

// meterWindow is the number of one-minute buckets a meter retains.
const meterWindow = 7

type sparkBucket struct {
	minute int64
	count  int
}

// meter counts events in one-minute buckets for sparkline and rate telemetry.
// It is not safe for concurrent use; owners guard it with their own lock.
type meter struct {
	total   int
	buckets []sparkBucket
}

func (m *meter) add(now time.Time, delta int) {
	if delta == 0 {
		return
	}
	m.total += delta
	minute := now.UTC().Unix() / 60
	if n := len(m.buckets); n > 0 && m.buckets[n-1].minute == minute {
		m.buckets[n-1].count += delta
	} else {
		m.buckets = append(m.buckets, sparkBucket{minute: minute, count: delta})
	}
	if len(m.buckets) > meterWindow {
		m.buckets = m.buckets[len(m.buckets)-meterWindow:]
	}
}

func (m *meter) active() bool {
	return m != nil && (m.total != 0 || len(m.buckets) > 0)
}

// snapshot returns the per-minute series, the lifetime total and the average
// per-minute rate across the retained buckets.
func (m *meter) snapshot() (series []int, total int, ratePerMin float64) {
	if m == nil {
		return []int{}, 0, 0
	}
	series = make([]int, len(m.buckets))
	windowTotal := 0
	for i, b := range m.buckets {
		series[i] = b.count
		windowTotal += b.count
	}
	if len(m.buckets) > 0 {
		minutes := float64(m.buckets[len(m.buckets)-1].minute-m.buckets[0].minute) + 1
		ratePerMin = float64(windowTotal) / minutes
	}
	return series, m.total, ratePerMin
}

// meterStatus renders primary and error meters with the service status keys.
func meterStatus(primary, errs *meter) map[string]any {
	spark, count, rate := primary.snapshot()
	errSpark, errCount, errRate := errs.snapshot()
	return map[string]any{
		"sparkline":           spark,
		"count":               count,
		"rate_per_min":        rate,
		"errors_sparkline":    errSpark,
		"errors_count":        errCount,
		"errors_rate_per_min": errRate,
	}
}
