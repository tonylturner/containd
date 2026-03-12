// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

package engineapp

import (
	"testing"

	"github.com/tonylturner/containd/pkg/cp/config"
)

func TestResolveRoutingIfacesMapsLogicalNamesToDevices(t *testing.T) {
	routing := config.RoutingConfig{
		Routes: []config.StaticRoute{
			{Dst: "default", Gateway: "wan-gw", Iface: "wan"},
			{Dst: "10.0.0.0/24", Iface: "eth9"},
		},
	}
	ifaces := []config.Interface{
		{Name: "wan", Device: "eth0"},
		{Name: "lan1", Device: "eth2"},
	}

	got := resolveRoutingIfaces(routing, ifaces)

	byDst := map[string]string{}
	for _, route := range got.Routes {
		byDst[route.Dst] = route.Iface
	}
	if byDst["default"] != "eth0" {
		t.Fatalf("expected logical route iface to resolve to eth0, got %q", byDst["default"])
	}
	if byDst["10.0.0.0/24"] != "eth9" {
		t.Fatalf("expected kernel iface to remain unchanged, got %q", byDst["10.0.0.0/24"])
	}
}

func TestResolveInterfaceRefsMapsLogicalNamesToDevices(t *testing.T) {
	ifaces := []config.Interface{
		{Name: "wan", Device: "eth0"},
		{Name: "lan1", Device: "eth2"},
	}

	got := resolveInterfaceRefs([]string{"lan1", "eth9", "wan"}, ifaces)
	want := []string{"eth2", "eth9", "eth0"}

	if len(got) != len(want) {
		t.Fatalf("expected %d interfaces, got %d (%v)", len(want), len(got), got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("index %d: expected %q, got %q", i, want[i], got[i])
		}
	}
}
