// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

package services

import (
	"testing"
	"time"
)

func TestAVManagerTelemetryCounts(t *testing.T) {
	m := &AVManager{}
	m.scans.add(time.Unix(1, 0), 7)
	m.scanErrs.add(time.Unix(1, 0), 2)
	m.detections = 3

	scans, scanErrors, detections := m.TelemetryCounts()
	if scans != 7 || scanErrors != 2 || detections != 3 {
		t.Fatalf("TelemetryCounts() = (%d, %d, %d), want (7, 2, 3)", scans, scanErrors, detections)
	}
}
