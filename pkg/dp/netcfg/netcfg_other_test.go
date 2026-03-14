// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

//go:build !linux

package netcfg

import (
	"context"
	"strings"
	"testing"

	"github.com/tonylturner/containd/pkg/cp/config"
)

func TestApplyInterfacesAndRoutingNoopOnUnsupportedPlatforms(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	ifaces := []config.Interface{{Name: "wan"}, {Name: "lan1"}}
	routing := config.RoutingConfig{
		Gateways: []config.Gateway{{Name: "wan", Iface: "wan", Address: "192.0.2.1"}},
	}

	if err := ApplyInterfaces(ctx, ifaces); err != nil {
		t.Fatalf("ApplyInterfaces returned error: %v", err)
	}
	if err := ApplyInterfacesReplace(ctx, ifaces); err != nil {
		t.Fatalf("ApplyInterfacesReplace returned error: %v", err)
	}
	if err := ApplyRouting(ctx, routing); err != nil {
		t.Fatalf("ApplyRouting returned error: %v", err)
	}
	if err := ApplyRoutingReplace(ctx, routing); err != nil {
		t.Fatalf("ApplyRoutingReplace returned error: %v", err)
	}
}

func TestWireGuardUnsupportedPlatformHelpers(t *testing.T) {
	t.Parallel()

	err := ApplyWireGuard(context.Background(), config.WireGuardConfig{})
	if err == nil || !strings.Contains(err.Error(), "not supported") {
		t.Fatalf("ApplyWireGuard error = %v, want unsupported platform error", err)
	}

	status, err := GetWireGuardStatus(context.Background(), "")
	if err == nil || !strings.Contains(err.Error(), "not supported") {
		t.Fatalf("GetWireGuardStatus error = %v, want unsupported platform error", err)
	}
	if status.Interface != "wg0" {
		t.Fatalf("status.Interface = %q, want wg0", status.Interface)
	}
	if status.Present {
		t.Fatal("expected Present=false on unsupported platform")
	}
}
