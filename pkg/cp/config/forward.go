// SPDX-License-Identifier: Apache-2.0
package config

import "fmt"

// ForwardAllowRule creates a collision-free, logged permission scoped to a
// forward's current selector. Creation does not place it in policy: appending
// it to arbitrary policy can shadow it. The forward ID is never inferred
// from description text, so renames/deletions are checked structurally.
func ForwardAllowRule(cfg *Config, forwardID string) Rule {
	used := map[string]bool{}
	for _, rule := range cfg.Firewall.Rules {
		used[rule.ID] = true
	}
	base := "pf-" + forwardID
	id := base
	for n := 1; used[id]; n++ {
		id = fmt.Sprintf("%s-%d", base, n)
	}
	return Rule{ID: id, Description: "Allows port forward " + forwardID, Action: ActionAllow, ViaForwards: []string{forwardID}, Log: true}
}
