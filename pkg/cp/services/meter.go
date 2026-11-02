// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

package services

import "time"

// meter retains lifetime totals only. Owners provide synchronization; retained
// history belongs to the management telemetry collector, not service status.
type meter struct {
	total  int
	used   bool
	signed bool
}

func (m *meter) add(_ time.Time, delta int) {
	m.total += delta
	m.used = m.used || delta != 0
	m.signed = m.signed || delta < 0
}
func (m *meter) active() bool { return m != nil && m.used }
func (m *meter) count() int {
	if m == nil {
		return 0
	}
	return m.total
}
func meterStatus(primary, errs *meter) map[string]any {
	return map[string]any{"count": primary.count(), "errors_count": errs.count()}
}
