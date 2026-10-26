// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

package verdict

import (
	"testing"

	"github.com/tonylturner/containd/pkg/dp/rules"
)

func TestFromRulesAction(t *testing.T) {
	for _, tc := range []struct {
		action rules.Action
		want   Action
		denies bool
	}{
		{rules.ActionAllow, AllowContinue, false},
		{rules.ActionDeny, DenyDrop, true},
		{rules.ActionReset, DenyReset, true},
		{rules.ActionRateLimit, DenyDrop, true},
		{rules.ActionTag, DenyDrop, true},
	} {
		got := FromRulesAction(tc.action)
		if got.Action != tc.want || got.Denies() != tc.denies {
			t.Fatalf("FromRulesAction(%s) = %s (denies %t), want %s (denies %t)", tc.action, got.Action, got.Denies(), tc.want, tc.denies)
		}
	}
}
