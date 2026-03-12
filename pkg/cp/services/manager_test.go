// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

package services

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/tonylturner/containd/pkg/cp/config"
)

func TestManagerApplyContinuesAfterServiceError(t *testing.T) {
	dir := t.TempDir()
	fakeEnvoy := filepath.Join(dir, "fake-envoy.sh")
	if err := os.WriteFile(fakeEnvoy, []byte("#!/bin/sh\nexit 1\n"), 0o755); err != nil {
		t.Fatalf("write fake envoy: %v", err)
	}
	mgr := &Manager{
		Proxy: NewProxyManager(ProxyOptions{
			BaseDir:   dir,
			Supervise: false,
			EnvoyPath: fakeEnvoy,
		}),
		AV: NewAVManager(),
	}

	cfg := config.ServicesConfig{
		Proxy: config.ProxyConfig{
			Forward: config.ForwardProxyConfig{
				Enabled:    true,
				ListenPort: 3128,
			},
		},
		AV: config.AVConfig{
			Enabled:    true,
			Mode:       "clamav",
			FailPolicy: "open",
			ClamAV: config.ClamAVConfig{
				SocketPath:       "/var/run/clamav/clamd.sock",
				FreshclamEnabled: true,
			},
		},
	}

	err := mgr.Apply(context.Background(), cfg)
	if err == nil {
		t.Fatal("expected proxy validation error")
	}
	if got := mgr.AV.Current().Mode; got != "clamav" {
		t.Fatalf("expected AV runtime config to still update, got mode %q", got)
	}
	if !mgr.AV.Current().Enabled {
		t.Fatal("expected AV runtime config to remain enabled")
	}
}
