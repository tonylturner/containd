// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

package config

import "testing"

func TestApplyBootstrapEnvDefaults(t *testing.T) {
	t.Setenv("CONTAIND_ENFORCE_ENABLED", "1")
	t.Setenv("CONTAIND_CAPTURE_IFACES", "eth0, eth1")

	cfg := DefaultConfig()
	if !cfg.DataPlane.DPIEnabled {
		t.Fatal("expected default config to enable DPI")
	}
	ApplyBootstrapEnvDefaults(cfg)

	if !cfg.DataPlane.Enforcement {
		t.Fatal("expected enforcement enabled from env")
	}
	if cfg.DataPlane.EnforceTable != "containd" {
		t.Fatalf("enforce table=%q want containd", cfg.DataPlane.EnforceTable)
	}
	want := []string{"eth0", "eth1"}
	if len(cfg.DataPlane.CaptureInterfaces) != len(want) {
		t.Fatalf("capture len=%d want %d", len(cfg.DataPlane.CaptureInterfaces), len(want))
	}
	for i := range want {
		if cfg.DataPlane.CaptureInterfaces[i] != want[i] {
			t.Fatalf("capture[%d]=%q want %q", i, cfg.DataPlane.CaptureInterfaces[i], want[i])
		}
	}
}
