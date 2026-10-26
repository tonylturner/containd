// SPDX-License-Identifier: Apache-2.0

package engineapp

import (
	"reflect"
	"testing"

	"go.uber.org/zap"

	"github.com/tonylturner/containd/pkg/cp/config"
	"github.com/tonylturner/containd/pkg/dp/coverage"
	"github.com/tonylturner/containd/pkg/dp/rules"
)

// The candidate preview evaluates the candidate's settings and the engine
// evaluates its own: for the same data plane both must agree on everything
// but runtime state. These settings need no queue, so no overlay applies.
func TestCandidateAndAppliedCoverageAgree(t *testing.T) {
	snap := rules.Snapshot{Firewall: []rules.Entry{
		{ID: "modbus", Action: rules.ActionAllow, Sources: []string{"10.0.0.5/32"},
			ICS: rules.ICSPredicate{Protocol: "modbus", FunctionCode: []uint8{3}}},
		{ID: "dnp3", Action: rules.ActionAllow, ICS: rules.ICSPredicate{Protocol: "dnp3", Mode: "learn"}},
		{ID: "iec", Action: rules.ActionAllow, ICS: rules.ICSPredicate{Protocol: "iec104", Mode: "enforce"}},
		{ID: "l4", Action: rules.ActionAllow, ICS: rules.ICSPredicate{Mode: "enforce"}},
	}}
	for name, dp := range map[string]config.DataPlaneConfig{
		"no inline path":                 {DPIEnabled: true, DPIMode: "enforce"},
		"dpi mock inspects with dpi off": {DPIMock: true, DPIMode: "enforce"},
		"decoder and dpi off":            {DPIMode: "enforce", DPIICSProtocols: map[string]bool{"modbus": false, "iec104": false}},
		"exclusions": {DPIEnabled: true, DPIMode: "enforce", DPIExclusions: []config.DPIExclusion{
			{Value: "10.0.0.5", Type: "ip"}, {Value: "192.0.2.0/24", Type: "cidr"}, {Value: "*.example.com", Type: "domain"}}},
		"queue without nft enforcement": {DPIEnabled: true, DPIMode: "enforce", NFQueueGroup: 101},
	} {
		t.Run(name, func(t *testing.T) {
			e, err := newEngineFor(zap.NewNop().Sugar(), dp, nil, nil)
			if err != nil {
				t.Fatal(err)
			}
			e.LoadRules(snap)
			want := coverage.Evaluate(&snap, dp.CoverageSettings())
			if len(want) != 3 {
				t.Fatalf("static coverage = %+v, want the three ICS rules", want)
			}
			if got := e.ICSCoverage(); !reflect.DeepEqual(got, want) {
				t.Fatalf("applied coverage %+v\ndiffers from candidate %+v", got, want)
			}
		})
	}
}
