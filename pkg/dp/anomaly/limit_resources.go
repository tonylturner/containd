// SPDX-License-Identifier: Apache-2.0

package anomaly

import "github.com/tonylturner/containd/pkg/dp/limits"

// SetLimits injects resolved configuration and accounting before the owner is
// published. It is not a live resizing API. Missing accounting dependencies
// are private and finite; traffic admission is not yet changed here.
func (d *Detector) SetLimits(l limits.Limits, budget *limits.Budget, ledger *limits.Ledger) {
	d.stateLimits = l
	d.resources = limits.NewResources(budget, ledger)
	d.writeRate.ledger = d.resources.Ledger
	d.totalRate.ledger = d.resources.Ledger
}
