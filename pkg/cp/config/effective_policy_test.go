// SPDX-License-Identifier: Apache-2.0
package config_test

import (
	"testing"

	"github.com/tonylturner/containd/pkg/cp/compile"
	"github.com/tonylturner/containd/pkg/cp/config"
)

func TestEffectiveAVPreservesClosedGate(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.DataPlane.Enforcement = true
	cfg.Services.AV = config.AVConfig{Enabled: true, Mode: "invalid",
		FailPolicy: "closed", HTTPDownload: true,
		Scan: config.ScanSelection{Include: []config.ScanInclude{{DestPorts: []string{"80"}}}}}
	effective, faults, err := config.Effective(cfg, nil)
	if err != nil || len(faults) != 1 || !effective.Services.AV.BackendDisabled {
		t.Fatalf("AV projection: %v %+v", err, faults)
	}
	snap, err := compile.CompileSnapshot(effective)
	if err != nil || !snap.Gate.Enabled || snap.Gate.FailPolicy != "closed" {
		t.Fatalf("AV quarantine weakened enforcement: %v %+v", err, snap.Gate)
	}
	if err := config.CheckWrite(nil, effective, nil); err == nil {
		t.Fatal("runtime projection accepted as desired state")
	}
}
