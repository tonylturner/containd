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

func TestResolveRoutingIfacesMapsGatewayLogicalNamesToDevices(t *testing.T) {
	routing := config.RoutingConfig{
		Gateways: []config.Gateway{
			{Name: "wan-gw", Address: "192.0.2.1", Iface: "wan"},
			{Name: "lab-gw", Address: "198.51.100.1", Iface: "eth9"},
			{Name: "any-gw", Address: "203.0.113.1"},
		},
		Routes: []config.StaticRoute{{Dst: "default", Gateway: "wan-gw"}},
	}
	ifaces := []config.Interface{{Name: "wan", Device: "eth0"}}

	got := resolveRoutingIfaces(routing, ifaces)

	want := map[string]string{"wan-gw": "eth0", "lab-gw": "eth9", "any-gw": ""}
	for _, gw := range got.Gateways {
		if gw.Iface != want[gw.Name] {
			t.Fatalf("gateway %s: expected iface %q, got %q", gw.Name, want[gw.Name], gw.Iface)
		}
	}
	if got.Routes[0].Iface != "" {
		t.Fatalf("expected a route without iface to keep using its gateway's iface, got %q", got.Routes[0].Iface)
	}
	if routing.Gateways[0].Iface != "wan" {
		t.Fatalf("expected caller's gateways to stay unchanged, got %q", routing.Gateways[0].Iface)
	}
}

func TestResolveRoutingIfacesMapsGatewaysWithoutRoutes(t *testing.T) {
	routing := config.RoutingConfig{
		Gateways: []config.Gateway{{Name: "wan-gw", Address: "192.0.2.1", Iface: "wan"}},
	}

	got := resolveRoutingIfaces(routing, []config.Interface{{Name: "wan", Device: "eth0"}})

	if got.Gateways[0].Iface != "eth0" {
		t.Fatalf("expected gateway iface to resolve to eth0 without routes, got %q", got.Gateways[0].Iface)
	}
}
