// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 containd Authors

package rules

import "testing"

func TestInvalidPortNeverMatchesZero(t *testing.T) {
	for _, port := range []string{"nft syntax", "3-1", "65536", "+1"} {
		snap := Snapshot{Default: ActionDeny, Firewall: []Entry{{ID: "bad", Action: ActionAllow, Protocols: []Protocol{{Name: "tcp", Port: port}}}}}
		if got := NewEvaluator(&snap).Evaluate(EvalContext{Proto: "tcp", Port: "0"}); got != ActionDeny {
			t.Errorf("invalid port %q matched: %s", port, got)
		}
	}
}
