// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

//go:build !linux

package engineapp

import (
	"context"
	"testing"

	"go.uber.org/zap"

	"github.com/tonylturner/containd/pkg/cp/config"
)

func TestOwnershipManagerStub(t *testing.T) {
	t.Parallel()

	mgr := newOwnershipManager(zap.NewNop().Sugar())
	mgr.setInterfaces([]config.Interface{{Name: "wan", Device: "eth0"}})
	mgr.setRouting(config.RoutingConfig{Routes: []config.StaticRoute{{Dst: "default", Gateway: "10.0.0.1"}}})
	mgr.start(context.Background())
	if got := mgr.currentInterfaces(); got != nil {
		t.Fatalf("stub currentInterfaces = %#v, want nil", got)
	}
	status := ownershipStatus(mgr)
	if enabled, ok := status["enabled"].(bool); !ok || enabled {
		t.Fatalf("unexpected ownership status: %#v", status)
	}
}
