// SPDX-License-Identifier: Apache-2.0
package enforce

import "github.com/tonylturner/containd/pkg/dp/rules"

func resolvedModes(snap *rules.Snapshot) *rules.Snapshot {
	copy := *snap
	copy.Firewall = append([]rules.Entry(nil), snap.Firewall...)
	for i := range copy.Firewall {
		if copy.Firewall[i].ICS.Protocol != "" {
			copy.Firewall[i].ICS.Mode = rules.EffectiveMode(copy.Firewall[i].ICS.Mode, snap.DPIMode)
		}
	}
	return &copy
}
