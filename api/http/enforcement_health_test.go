// SPDX-License-Identifier: Apache-2.0
package httpapi

import (
	"testing"

	"github.com/tonylturner/containd/pkg/cp/config"
	dpengine "github.com/tonylturner/containd/pkg/dp/engine"
)

func TestEnforcementHealthLabelsDegradedComponents(t *testing.T) {
	tests := []struct {
		name       string
		component  dpengine.ProtectionComponent
		wantReason string
	}{
		{
			name: "interface attachment",
			component: dpengine.ProtectionComponent{
				Name: "interface-attachment", State: "degraded",
				Reason: "zone lan has no attached interface: lan1, lan2",
			},
			wantReason: "interface-attachment: zone lan has no attached interface: lan1, lan2",
		},
		{
			name: "NFLOG",
			component: dpengine.ProtectionComponent{
				Name: "nflog", State: "failed", Reason: "private nft source 192.0.2.7",
			},
			wantReason: "rule-hit logging unavailable; nft policy enforcing",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := enforcementHealth(
				config.HealthSnapshot{Config: config.DefaultConfig()},
				nil,
				rulesetObservation{},
				dpengine.ProtectionStatus{
					State:      "degraded",
					Components: []dpengine.ProtectionComponent{tc.component},
				},
			)
			if got["state"] != "degraded" || got["reason"] != tc.wantReason {
				t.Fatalf("enforcementHealth() = %v, want degraded reason %q", got, tc.wantReason)
			}
			if tc.name == "NFLOG" && got["reason"] == tc.component.Reason {
				t.Fatalf("NFLOG diagnostics leaked through health: %v", got)
			}
		})
	}
}
