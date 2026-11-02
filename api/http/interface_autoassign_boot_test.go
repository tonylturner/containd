// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

package httpapi

import (
	"net/netip"
	"strings"
	"testing"

	"github.com/tonylturner/containd/pkg/common/mgmtpath"
	"github.com/tonylturner/containd/pkg/cp/config"
)

func clearBootSubnetOverrides(t *testing.T) {
	t.Helper()
	for _, name := range config.DefaultPhysicalInterfaces() {
		t.Setenv("CONTAIND_AUTO_"+strings.ToUpper(name)+"_SUBNET", "")
		t.Setenv("CONTAIND_"+strings.ToUpper(name)+"_SUBNET", "")
	}
}

func TestBootAutobindKeepsPresentBindingsWithoutContradictingEvidence(t *testing.T) {
	clearBootSubnetOverrides(t)
	cfg := &config.Config{Interfaces: []config.Interface{
		{Name: "lan1", Zone: "lan", Device: "eth0", Addresses: []string{"172.29.40.2/24"}},
		{Name: "wan", Zone: "wan", Device: "eth1", Addresses: []string{"172.29.41.2/24"}},
	}}
	state := []config.InterfaceState{
		{Name: "eth0", Index: 2, Up: true, Addrs: []string{"172.29.40.2/24"}},
		{Name: "eth1", Index: 3, Up: true, Addrs: []string{"172.29.41.2/24"}},
	}

	if autoBindDefaultInterfaceDevicesReservedFromState(cfg, state, "eth1", nil) {
		t.Fatal("unchanged, address-consistent bindings were rewritten")
	}
	if got := devices(cfg.Interfaces); got["lan1"] != "eth0" || got["wan"] != "eth1" {
		t.Fatalf("bindings changed: %v", got)
	}
}

func TestBootAutobindRepairsSwappedAddresses(t *testing.T) {
	clearBootSubnetOverrides(t)
	cfg := &config.Config{Interfaces: []config.Interface{
		{Name: "lan1", Zone: "lan", Device: "eth0", Addresses: []string{"172.29.40.2/24"}},
		{Name: "wan", Zone: "wan", Device: "eth1", Addresses: []string{"172.29.41.2/24"}},
	}}
	state := []config.InterfaceState{
		{Name: "eth0", Index: 2, Up: true, Addrs: []string{"172.29.41.2/24"}},
		{Name: "eth1", Index: 3, Up: true, Addrs: []string{"172.29.40.2/24"}},
	}

	if !autoBindDefaultInterfaceDevicesReservedFromState(cfg, state, "eth0", nil) {
		t.Fatal("swapped current addresses did not trigger repair")
	}
	if got := devices(cfg.Interfaces); got["lan1"] != "eth1" || got["wan"] != "eth0" {
		t.Fatalf("swapped bindings not repaired: %v", got)
	}
}

func TestBootAutobindRepairsMissingDevice(t *testing.T) {
	clearBootSubnetOverrides(t)
	cfg := &config.Config{Interfaces: []config.Interface{
		{Name: "wan", Zone: "wan", Device: "eth9", Addresses: []string{"172.29.41.2/24"}},
	}}
	state := []config.InterfaceState{
		{Name: "eth0", Index: 2, Up: true, Addrs: []string{"172.29.41.2/24"}},
	}

	if !autoBindDefaultInterfaceDevicesReservedFromState(cfg, state, "eth0", nil) {
		t.Fatal("missing kernel device did not trigger repair")
	}
	if got := cfg.Interfaces[0].Device; got != "eth0" {
		t.Fatalf("missing binding repaired to %q, want eth0", got)
	}
}

func TestBootAutobindCommittedAddressesPrecedeDefaultSubnets(t *testing.T) {
	clearBootSubnetOverrides(t)
	cfg := &config.Config{Interfaces: []config.Interface{
		{Name: "wan", Zone: "wan", Device: "eth0", Addresses: []string{"172.29.41.2/24"}},
	}}
	state := []config.InterfaceState{
		{Name: "eth0", Index: 2, Up: true, Addrs: []string{"172.29.40.2/24"}},
		{Name: "eth1", Index: 3, Up: true, Addrs: []string{"172.29.41.2/24"}},
		{Name: "eth2", Index: 4, Up: true, Addrs: []string{"192.168.240.2/24"}},
	}

	if !autoBindDefaultInterfaceDevicesReservedFromState(cfg, state, "eth2", nil) {
		t.Fatal("contradictory binding did not trigger repair")
	}
	if got := cfg.Interfaces[0].Device; got != "eth1" {
		t.Fatalf("committed address assignment lost to default subnet: got %q, want eth1", got)
	}
}

func TestBootAutobindSubnetAuthorityOverridesCommittedAddress(t *testing.T) {
	clearBootSubnetOverrides(t)
	t.Setenv("CONTAIND_AUTO_WAN_SUBNET", "172.29.41.0/24")
	t.Setenv("CONTAIND_AUTO_LAN1_SUBNET", "172.29.40.0/24")
	cfg := &config.Config{Interfaces: []config.Interface{
		{Name: "lan1", Zone: "lan", Device: "eth1", Addresses: []string{"172.29.41.2/24"}},
		{Name: "wan", Zone: "wan", Device: "eth0", Addresses: []string{"172.29.40.2/24"}},
	}}
	state := []config.InterfaceState{
		{Name: "eth0", Index: 2, Up: true, Addrs: []string{"172.29.40.2/24"}},
		{Name: "eth1", Index: 3, Up: true, Addrs: []string{"172.29.41.2/24"}},
	}

	if !autoBindDefaultInterfaceDevicesReservedFromState(cfg, state, "eth0", nil) {
		t.Fatal("subnet authority did not trigger repair")
	}
	if got := devices(cfg.Interfaces); got["wan"] != "eth1" || got["lan1"] != "eth0" {
		t.Fatalf("explicit subnet authority lost: %v", got)
	}
}

func TestBootAutobindReservationFollowsItsSubnetOwner(t *testing.T) {
	clearBootSubnetOverrides(t)
	t.Setenv("CONTAIND_AUTO_WAN_SUBNET", "10.10.10.0/24")
	t.Setenv("CONTAIND_AUTO_LAN3_SUBNET", "10.99.99.0/24")
	r := &mgmtpath.Reservation{
		Device: "eth0",
		Local:  netip.MustParsePrefix("10.99.99.2/24"),
		Port:   8080,
	}
	state := []config.InterfaceState{
		{Name: "eth0", Index: 2, Up: true, Addrs: []string{"10.99.99.3/24"}},
		{Name: "eth4", Index: 3, Up: true, Addrs: []string{"10.10.10.3/24"}},
	}
	cfg := &config.Config{Interfaces: []config.Interface{
		{Name: "wan", Zone: "wan", Device: "eth0"},
		{Name: "lan3", Zone: "lan", Device: "eth4"},
	}}
	if err := config.ValidateManagementInterfaces(cfg.Interfaces, r); err != nil {
		t.Fatalf("reservation setup invalid: %v", err)
	}

	if !repairDefaultInterfaceDevicesReservedFromState(cfg, state, "eth0", r) {
		t.Fatal("stale reserved binding was not moved to the authoritative subnet owner")
	}
	if got := devices(cfg.Interfaces); got["wan"] != "eth4" || got["lan3"] != "eth0" {
		t.Fatalf("reservation or subnet authority changed: %v", got)
	}

	cfg.Interfaces[0].Device, cfg.Interfaces[1].Device = "eth4", "eth0"
	if repairDefaultInterfaceDevicesReservedFromState(cfg, state, "eth0", r) {
		t.Fatal("consistent reservation owner was rewritten")
	}
}
