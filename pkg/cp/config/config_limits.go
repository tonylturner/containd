// SPDX-License-Identifier: Apache-2.0

package config

import "github.com/tonylturner/containd/pkg/dp/limits"

type DataPlaneLimits struct {
	MaxFlows           int   `json:"maxFlows,omitempty"`
	MaxTopTalkers      int   `json:"maxTopTalkers,omitempty"`
	MaxInspectionBytes int64 `json:"maxInspectionBytes,omitempty"`
}

// Effective resolves omitted fields without rewriting the stored configuration.
func (l DataPlaneLimits) Effective() limits.Limits {
	out := limits.Default()
	if l.MaxFlows != 0 {
		out.MaxFlows = l.MaxFlows
	}
	if l.MaxTopTalkers != 0 {
		out.MaxTopTalkers = l.MaxTopTalkers
	}
	if l.MaxInspectionBytes != 0 {
		out.MaxInspectionBytes = l.MaxInspectionBytes
	}
	return out
}
