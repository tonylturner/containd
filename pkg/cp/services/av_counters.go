// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

package services

// TelemetryCounts returns lifetime scan, scan error, and detection totals
// without probing the antivirus backend.
func (m *AVManager) TelemetryCounts() (scans, scanErrors, detections uint64) {
	if m == nil {
		return 0, 0, 0
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	return uint64(m.scans.total), uint64(m.scanErrs.total), uint64(m.detections)
}
