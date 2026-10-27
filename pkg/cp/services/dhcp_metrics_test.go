// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

package services

import "testing"

// Lease failures count on the DHCP error meter that the status reports as
// errors_*, and issued leases on its primary meter.
func TestDHCPLeaseFailuresCountAsDHCPErrors(t *testing.T) {
	mgr := NewManager(ManagerOptions{BaseDir: t.TempDir()})
	mgr.DHCP.IncrementLeaseMetric(2, false)
	mgr.DHCP.IncrementLeaseMetric(1, true)

	status, ok := mgr.Status().(map[string]any)
	if !ok {
		t.Fatal("manager Status did not return a map")
	}
	dhcp, ok := status["dhcp"].(map[string]any)
	if !ok {
		t.Fatalf("manager status dhcp = %#v", status["dhcp"])
	}
	if got := dhcp["count"]; got != 2 {
		t.Errorf("dhcp count = %#v, want 2", got)
	}
	if got := dhcp["errors_count"]; got != 1 {
		t.Errorf("dhcp errors_count = %#v, want 1", got)
	}
	if mgr.hasMetrics("dhcp_error") {
		t.Error("lease failures recorded under a separate dhcp_error service")
	}
}
