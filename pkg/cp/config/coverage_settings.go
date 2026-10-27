// SPDX-License-Identifier: Apache-2.0

package config

import "github.com/tonylturner/containd/pkg/dp/coverage"

// CoverageSettings maps the data-plane settings to the inputs of an ICS
// coverage evaluation, as the engine built from them runs: the lab DPI mock
// inspects even when the DPI master switch is off.
func (dp DataPlaneConfig) CoverageSettings() coverage.Settings {
	s := coverage.Settings{
		Enforcement:  dp.Enforcement,
		QueueID:      dp.NFQueueGroup,
		DPIEnabled:   dp.DPIEnabled || dp.DPIMock,
		DPIMode:      dp.DPIMode,
		ICSProtocols: dp.DPIICSProtocols,
	}
	for _, x := range dp.DPIExclusions {
		s.Exclusions = append(s.Exclusions, coverage.Exclusion{Value: x.Value, Type: x.Type})
	}
	return s
}
