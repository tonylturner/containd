// SPDX-License-Identifier: Apache-2.0
package rules

import "github.com/tonylturner/containd/pkg/dp/ics"

// ValidateIndustrialProtocols guards snapshots received without CP compilation.
// Validation happens before enforcement or the atomic snapshot swap.
func (s Snapshot) ValidateIndustrialProtocols() error {
	for _, r := range s.Firewall {
		if err := ics.ValidateRule(r.ID, r.ICS.Protocol); err != nil {
			return err
		}
	}
	for _, r := range s.IDS.Rules {
		if err := ics.ValidateIDS(r.ID, r.Proto); err != nil {
			return err
		}
	}
	return nil
}
