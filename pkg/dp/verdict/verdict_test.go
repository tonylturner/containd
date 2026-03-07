// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

package verdict

import (
	"testing"

	"github.com/tonylturner/containd/pkg/dp/rules"
)

func TestFromRulesAction(t *testing.T) {
	if got := FromRulesAction(rules.ActionAllow); got.Action != AllowContinue {
		t.Fatalf("expected allow verdict, got %s", got.Action)
	}
	if got := FromRulesAction(rules.ActionDeny); got.Action != DenyDrop {
		t.Fatalf("expected deny verdict, got %s", got.Action)
	}
}

