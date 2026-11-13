// SPDX-License-Identifier: Apache-2.0

package signatures

import "github.com/tonylturner/containd/pkg/dp/limits"

// SetLimits injects resolved configuration and accounting before the owner is
// published. It is not a live resizing API. Missing accounting dependencies
// are private and finite; traffic admission is not yet changed here.
func (e *Engine) SetLimits(l limits.Limits, budget *limits.Budget, ledger *limits.Ledger) {
	e.stateLimits = l
	e.resources = limits.NewResources(budget, ledger)
}
