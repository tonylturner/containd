// SPDX-License-Identifier: Apache-2.0

package config

import (
	"strings"
	"testing"
)

// Configuration applies the engine's table name rule: nft's identifier
// syntax without nft keywords or the DHCP redirect table, with room for the
// "_policy" table within the kernel's 255 bytes.
func TestValidateEnforceTable(t *testing.T) {
	for _, tc := range []struct {
		name string
		ok   bool
	}{
		{"", true},
		{"containd", true},
		{"fw", true},
		{"FW_Lab", true},
		{"_fw", true},
		{"fw-1", true},
		{"a1", true},
		{"containd_policy", true},
		{"containd_dhcp_policy", true},
		{strings.Repeat("a", 248), true},
		{strings.Repeat("a", 249), false},
		{"1fw", false},
		{"9", false},
		{"-fw", false},
		{"bad space", false},
		{"fw.lab", false},
		{"fw/lab", false},
		{`"fw"`, false},
		{"containd_dhcp", false},
		{"table", false},
		{"inet", false},
		{"accept", false},
		{"auto-merge", false},
		{"Table", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := validateDataPlane(DataPlaneConfig{Enforcement: true, EnforceTable: tc.name})
			if (err == nil) != tc.ok {
				t.Fatalf("validateDataPlane(enforceTable=%q) = %v, want ok=%v", tc.name, err, tc.ok)
			}
		})
	}
}
