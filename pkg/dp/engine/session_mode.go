// SPDX-License-Identifier: Apache-2.0
package engine

import (
	"github.com/tonylturner/containd/pkg/dp/flow"
	"github.com/tonylturner/containd/pkg/dp/rules"
)

// Generic passive capture never acquires inline authority, even inside an
// enforcing policy envelope. Retain that admission fact across publication.
func (t *sessionTable) effectiveModeLocked(ctx rules.EvalContext, state *flow.State, inline bool) (bool, string) {
	matched, mode := t.envelopeLocked(ctx)
	if !inline && sessionProtocol(state) != iecProtocol {
		mode = "monitor"
	}
	return matched, mode
}
