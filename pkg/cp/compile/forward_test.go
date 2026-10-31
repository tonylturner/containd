// SPDX-License-Identifier: Apache-2.0
package compile

import (
	"encoding/json"
	"net/netip"
	"reflect"
	"testing"

	"github.com/tonylturner/containd/pkg/cp/config"
	"github.com/tonylturner/containd/pkg/dp/markabi"
	"github.com/tonylturner/containd/pkg/dp/rules"
)

func forwardConfig() *config.Config {
	cfg := config.DefaultConfig()
	cfg.Interfaces = []config.Interface{{Name: "wan", Zone: "wan", Device: "wan0"}}
	cfg.Firewall.NAT.Enabled = false
	cfg.Firewall.NAT.PortForwards = []config.PortForward{{ID: "f", Enabled: true, IngressZone: "wan", Proto: "tcp", ListenPort: 1502,
		DestIP: "10.0.0.8", DestPort: 502, AllowedSources: []string{"198.51.100.3/24"}}}
	cfg.Firewall.Rules = []config.Rule{{ID: "via", Action: config.ActionAllow, ViaForwards: []string{"f"}}}
	return cfg
}

func TestCompileForwardMatchesAndRuntimeInputs(t *testing.T) {
	cfg := forwardConfig()
	in := SnapshotInputs{AdmissionParity: markabi.ParityBit, LocalIPv4ByDevice: map[string][]netip.Addr{"wan0": {
		netip.MustParseAddr("203.0.113.2"), netip.MustParseAddr("203.0.113.1"), netip.MustParseAddr("203.0.113.2")}}}
	snap, err := CompileSnapshotWithInputs(cfg, in)
	if err != nil {
		t.Fatal(err)
	}
	want := rules.ForwardMatch{Enabled: true, IngressDevices: []string{"wan0"}, Protocol: "tcp", ListenPort: 1502,
		Backend: netip.MustParseAddrPort("10.0.0.8:502"), AllowedSources: []netip.Prefix{netip.MustParsePrefix("198.51.100.0/24")}}
	if snap.AdmissionParity != markabi.ParityBit || !reflect.DeepEqual(snap.ForwardMatches["f"], want) {
		t.Fatalf("snapshot = %+v", snap)
	}
	if len(snap.LocalIPv4ByDevice["wan0"]) != 2 || snap.LocalIPv4ByDevice["wan0"][0] != netip.MustParseAddr("203.0.113.1") {
		t.Fatal("local addresses not canonical")
	}
	raw, err := json.Marshal(snap)
	if err != nil {
		t.Fatal(err)
	}
	var received rules.Snapshot
	if err := json.Unmarshal(raw, &received); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(received.ForwardMatches, snap.ForwardMatches) || !reflect.DeepEqual(received.LocalIPv4ByDevice, snap.LocalIPv4ByDevice) || received.AdmissionParity != snap.AdmissionParity {
		t.Fatal("runtime evidence lost on internal wire")
	}
	cfg.Firewall.Rules[0].ViaForwards[0] = "edited"
	cfg.Firewall.NAT.PortForwards[0].AllowedSources[0] = "0.0.0.0/0"
	cfg.Interfaces[0].Device = "edited"
	in.LocalIPv4ByDevice["wan0"][0] = netip.MustParseAddr("192.0.2.1")
	if snap.Firewall[0].ViaForwards[0] != "f" || !reflect.DeepEqual(snap.ForwardMatches["f"], want) || snap.LocalIPv4ByDevice["wan0"][1] != netip.MustParseAddr("203.0.113.2") {
		t.Fatal("snapshot aliases input")
	}
}

func TestCompileDisabledUnboundAndExplicitForward(t *testing.T) {
	for _, mutate := range []func(*config.Config){
		func(c *config.Config) { c.Firewall.NAT.PortForwards[0].Enabled = false },
		func(c *config.Config) { c.Interfaces[0].Device = "" },
	} {
		cfg := forwardConfig()
		mutate(cfg)
		snap, err := CompileSnapshot(cfg)
		if err != nil || len(snap.ForwardMatches) != 0 || len(snap.Firewall[0].ViaForwards) != 1 {
			t.Fatalf("disabled/unbound widened: %+v, %v", snap, err)
		}
	}
	cfg := forwardConfig()
	cfg.Firewall.NAT.PortForwards[0].ListenAddress = "203.0.113.9"
	cfg.Firewall.NAT.PortForwards[0].DestPort = 0
	snap, err := CompileSnapshot(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if f := snap.ForwardMatches["f"]; f.ListenAddress != netip.MustParseAddr("203.0.113.9") || f.Backend.Port() != 1502 || snap.NAT.PortForwards[0].ListenAddress != "203.0.113.9" {
		t.Fatal("lost listen or effective destination port")
	}
}

func TestCompileRuntimeInputValidation(t *testing.T) {
	for _, in := range []SnapshotInputs{
		{AdmissionParity: 1}, {AdmissionParity: markabi.AdmittedBit | markabi.ParityBit},
		{LocalIPv4ByDevice: map[string][]netip.Addr{"": {}}},
		{LocalIPv4ByDevice: map[string][]netip.Addr{"wan0": {netip.MustParseAddr("2001:db8::1")}}},
		{PreviousGateZones: []rules.GateZone{{Name: "wan", Index: 0}}},
		{PreviousGateZones: []rules.GateZone{{Name: "wan", Index: 1}, {Name: "lan", Index: 1}}},
	} {
		if _, err := CompileSnapshotWithInputs(forwardConfig(), in); err == nil {
			t.Fatalf("accepted invalid inputs: %+v", in)
		}
	}
}

func TestCompileRetainsGateZoneIndicesAcrossReorder(t *testing.T) {
	cfg := gateConfig(func(*config.Config) {})
	first, err := CompileSnapshot(cfg)
	if err != nil {
		t.Fatal(err)
	}
	cfg.Zones[0], cfg.Zones[3] = cfg.Zones[3], cfg.Zones[0]
	cfg.Services.AV.Scan.Include[0].DestZones = []string{"void", "wan", "ot"}
	second, err := CompileSnapshotWithInputs(cfg, SnapshotInputs{PreviousGateZones: first.Gate.Zones})
	if err != nil {
		t.Fatal(err)
	}
	indices := map[string]uint8{}
	for _, zone := range second.Gate.Zones {
		indices[zone.Name] = zone.Index
	}
	if indices["wan"] != 1 || indices["void"] != 2 || indices["ot"] != 3 {
		t.Fatalf("indices changed: %+v", indices)
	}
}
