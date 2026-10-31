// SPDX-License-Identifier: Apache-2.0

package config

import (
	"fmt"

	"github.com/tonylturner/containd/pkg/dp/rules"
)

// validateICSEnforcePath rejects a rule that names an ICS protocol and is in
// effective enforce mode while no inline path exists. Without NFQUEUE the
// engine only observes copies of packets, so the first prohibited command
// would reach the device. Rules without a protocol and explicit monitor rules
// are unaffected, and a global enforce mode alone needs no queue.
func validateICSEnforcePath(c *Config) error {
	if c.DataPlane.NFQueueGroup != 0 {
		return nil
	}
	for _, r := range c.Firewall.Rules {
		if r.ICS.Protocol == "" || rules.EffectiveMode(r.ICS.Mode, c.DataPlane.DPIMode) != "enforce" {
			continue
		}
		return fmt.Errorf("rule %s: %s enforce needs an inline path to stop a prohibited command; "+
			"set dataplane.nfqueueGroup to a non-zero queue, or set the rule's ics.mode to monitor", r.ID, r.ICS.Protocol)
	}
	return nil
}
