// SPDX-License-Identifier: Apache-2.0

package engineapi

import "github.com/tonylturner/containd/pkg/cp/config"

// ServicesApplyResult reports independent runtime outcomes. Request failures
// remain HTTP errors; an empty fault set means every attempted apply succeeded.
type ServicesApplyResult struct {
	Faults   []config.ServiceFault `json:"faults"`
	Warnings []string              `json:"warnings,omitempty"`
}
