// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

package httpapi

import (
	"context"
	"testing"

	engineclient "github.com/tonylturner/containd/api/engine"
	"github.com/tonylturner/containd/pkg/cp/config"
	dpengine "github.com/tonylturner/containd/pkg/dp/engine"
	"github.com/tonylturner/containd/pkg/dp/netcfg"
)

type forwardingWarningMockEngine struct {
	*mockEngine
	status netcfg.IPv4ForwardingStatus
	calls  int
}

func (m *forwardingWarningMockEngine) RuntimeHealth(context.Context) (engineclient.RuntimeHealth, error) {
	m.calls++
	return engineclient.RuntimeHealth{
		IEC104Enforcement: dpengine.IEC104Enforcement{Healthy: true},
		IPv4Forwarding:    m.status,
	}, nil
}

func TestApplyRunningConfigWarnsWhenIPv4ForwardingDisabled(t *testing.T) {
	t.Parallel()

	engine := &forwardingWarningMockEngine{
		mockEngine: &mockEngine{},
		status:     netcfg.IPv4ForwardingDisabled,
	}
	warnings, err := applyRunningConfig(context.Background(), &mockStore{cfg: config.DefaultConfig()}, engine, nil)
	if err != nil {
		t.Fatalf("applyRunningConfig() error = %v", err)
	}
	count := 0
	for _, warning := range warnings {
		if warning == ipv4ForwardingWarning {
			count++
		}
	}
	if count != 1 {
		t.Fatalf("forwarding warning count = %d in %v, want one", count, warnings)
	}
	if engine.calls != 1 {
		t.Fatalf("RuntimeHealth calls = %d, want 1", engine.calls)
	}
}

func TestIPv4ForwardingCommitWarningRequiresMultipleZoneDevices(t *testing.T) {
	t.Parallel()

	engine := &forwardingWarningMockEngine{
		mockEngine: &mockEngine{},
		status:     netcfg.IPv4ForwardingDisabled,
	}
	cfg := &config.Config{Interfaces: []config.Interface{{Name: "lan", Zone: "lan"}}}
	if warning := ipv4ForwardingCommitWarning(context.Background(), cfg, engine); warning != "" {
		t.Fatalf("warning for a single zone device = %q, want none", warning)
	}
	if engine.calls != 0 {
		t.Fatalf("RuntimeHealth calls = %d, want none", engine.calls)
	}
}
