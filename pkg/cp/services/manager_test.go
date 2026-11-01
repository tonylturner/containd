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
		DHCP: NewDHCPManager(dir),
	}

	cfg := config.ServicesConfig{
		Proxy: config.ProxyConfig{
			Forward: config.ForwardProxyConfig{
				Enabled:    true,
				ListenPort: 3128,
			},
		},
		DHCP: config.DHCPConfig{Enabled: true},
	}

	_, warnings := mgr.ApplyEffective(context.Background(), cfg, nil)
	if len(warnings) == 0 {
		t.Fatal("expected proxy validation error")
	}
	if !mgr.DHCP.Current().Enabled {
		t.Fatal("expected DHCP to apply after the proxy error")
	}
}
