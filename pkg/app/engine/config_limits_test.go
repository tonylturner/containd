// SPDX-License-Identifier: Apache-2.0

package engineapp

import (
	"testing"

	"github.com/tonylturner/containd/pkg/cp/config"
	"github.com/tonylturner/containd/pkg/dp/engine"
	"github.com/tonylturner/containd/pkg/dp/limits"
	"go.uber.org/zap"
)

func TestSameDataPlaneEffectiveLimits(t *testing.T) {
	a := config.DataPlaneConfig{}
	d := limits.Default()
	b := config.DataPlaneConfig{Limits: config.DataPlaneLimits{MaxFlows: d.MaxFlows, MaxTopTalkers: d.MaxTopTalkers, MaxInspectionBytes: d.MaxInspectionBytes}}
	if !sameDataPlane(a, b) || !sameDataPlane(b, a) {
		t.Fatal("explicit defaults caused a rebuild")
	}
	for _, change := range []config.DataPlaneLimits{{MaxFlows: 2048}, {MaxTopTalkers: 64}, {MaxInspectionBytes: 8 << 20}} {
		b.Limits = change
		if sameDataPlane(a, b) {
			t.Fatalf("ignored limit change %+v", change)
		}
	}
	if a.Limits != (config.DataPlaneLimits{}) {
		t.Fatal("comparison rewrote stored defaults")
	}
}
func TestConfigBuildSharesLedger(t *testing.T) {
	cfg := initialEngineConfig(nil, false, "")
	if cfg.Ledger == nil {
		t.Fatal("assembly omitted process ledger")
	}
	e, err := engine.New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer e.Close()
	ledger := e.Ledger()
	ledger.Record(limits.TableFlows, limits.ReasonRefused, limits.ModeMonitor)
	fresh, err := newEngineFor(zap.NewNop().Sugar(), config.DataPlaneConfig{Limits: config.DataPlaneLimits{MaxFlows: 2048}}, e.Events(), nil, ledger)
	if err != nil {
		t.Fatal(err)
	}
	if fresh.Ledger() != ledger {
		t.Fatal("builder discarded process ledger")
	}
	if err := e.Reconfigure(fresh); err != nil {
		t.Fatal(err)
	}
	if s := e.StateLimits(); len(s.Tables[0].Hits) != 1 || s.Tables[0].Hits[0].Total != 1 {
		t.Fatal("rebuild lost process totals")
	}
}
