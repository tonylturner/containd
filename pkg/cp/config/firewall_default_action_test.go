// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 containd Authors

package config

import (
	"fmt"
	"testing"
)

func TestEffectiveDefaultAction(t *testing.T) {
	for _, tc := range []struct {
		stored Action
		want   Action
	}{
		{"", ActionDeny},
		{ActionAllow, ActionAllow},
		{ActionDeny, ActionDeny},
		{"allow", ActionDeny},
		{" ALLOW", ActionDeny},
		{"ACCEPT", ActionDeny},
	} {
		t.Run(fmt.Sprintf("%q", tc.stored), func(t *testing.T) {
			got := FirewallConfig{DefaultAction: tc.stored}.EffectiveDefaultAction()
			if got != tc.want {
				t.Fatalf("EffectiveDefaultAction(%q) = %q, want %q", tc.stored, got, tc.want)
			}
		})
	}
}
