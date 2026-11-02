// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

package services

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/tonylturner/containd/pkg/common/protection"
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

	_, warnings := applyManagerTest(t, mgr, cfg, nil)
	if len(warnings) == 0 {
		t.Fatal("expected proxy validation error")
	}
	if !mgr.DHCP.Current().Enabled {
		t.Fatal("expected DHCP to apply after the proxy error")
	}
}

func deliveryTestMeta() protection.Metadata {
	return protection.Metadata{BootID: "boot", ApplyID: "apply", RunningRevision: "revision", Mode: protection.ModeNormal}
}

func applyManagerTest(t *testing.T, m *Manager, cfg config.ServicesConfig, initial []config.ServiceConfigError) (config.ServicesConfig, []string) {
	t.Helper()
	result, err := m.ApplyDelivery(context.Background(), deliveryTestMeta(), cfg, initial)
	if err != nil {
		t.Fatal(err)
	}
	var failures []string
	for _, out := range result.Outcomes {
		if out.Fault != nil {
			failures = append(failures, out.Reason)
		}
	}
	return result.Effective, failures
}
