// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

package engineapp

import "testing"

func TestInitialEngineConfigEnablesDPIByDefault(t *testing.T) {
	cfg := initialEngineConfig([]string{"wan"}, false, "containd")
	if !cfg.DPIEnabled {
		t.Fatal("expected initial engine config to enable DPI by default")
	}
	if cfg.InspectAll {
		t.Fatal("expected inspect-all to remain disabled without lab mode")
	}
}
