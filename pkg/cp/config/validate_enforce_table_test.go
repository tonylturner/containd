// SPDX-License-Identifier: Apache-2.0

package config

import (
	"strings"
	"testing"
)

// The accepted names are the unquoted table names nft 1.1 parses, with room
// for the engine's "_blocks" companion table within the 255-byte limit.
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
		{"containd_blocks", true},
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
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := validateDataPlane(DataPlaneConfig{Enforcement: true, EnforceTable: tc.name})
			if (err == nil) != tc.ok {
				t.Fatalf("validateDataPlane(enforceTable=%q) = %v, want ok=%v", tc.name, err, tc.ok)
			}
		})
	}
}
