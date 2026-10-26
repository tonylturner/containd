// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 containd Authors

package config

import (
	"fmt"
	"strings"
	"testing"
)

func TestValidateFirewallDefaultAction(t *testing.T) {
	for _, tc := range []struct {
		action Action
		valid  bool
	}{
		{"", true},
		{ActionAllow, true},
		{ActionDeny, true},
		{"allow", false},
		{"deny", false},
		{"Deny", false},
		{" DENY", false},
		{"DENY ", false},
		{"DROP", false},
		{"REJECT", false},
		{"ACCEPT", false},
		{"LOG", false},
	} {
		t.Run(fmt.Sprintf("%q", tc.action), func(t *testing.T) {
			cfg := DefaultConfig()
			cfg.Firewall.DefaultAction = tc.action
			err := cfg.Validate()
			if tc.valid {
				if err != nil {
					t.Fatalf("defaultAction %q rejected: %v", tc.action, err)
				}
				return
			}
			if err == nil {
				t.Fatalf("defaultAction %q accepted", tc.action)
			}
			for _, want := range []string{"firewall.defaultAction", `"ALLOW"`, `"DENY"`} {
				if !strings.Contains(err.Error(), want) {
					t.Errorf("defaultAction %q error %q does not mention %s", tc.action, err, want)
				}
			}
		})
	}
}
