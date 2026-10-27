// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 containd Authors

package compile

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"

	"github.com/tonylturner/containd/pkg/cp/config"
	"github.com/tonylturner/containd/pkg/dp/rules"
)

// gateConfig scans lan->wan downloads. Zone lan has a bound device and an
// unbound interface, wan a bound device, ot an addressed interface, and
// void no interface at all.
func gateConfig(mut func(*config.Config)) *config.Config {
	cfg := &config.Config{
		System: config.SystemConfig{Hostname: "containd"},
		Zones:  []config.Zone{{Name: "wan"}, {Name: "lan"}, {Name: "ot"}, {Name: "void"}},
		Interfaces: []config.Interface{
			{Name: "wan", Zone: "wan", Device: "eth0"},
			{Name: "lan2", Zone: "lan", Device: "eth2"},
			{Name: "lan3", Zone: "lan"},
			{Name: "ot0", Zone: "ot", Addresses: []string{"10.1.0.1/24", "2001:db8:1::1/64"}},
		},
		Assets: []config.Asset{
			{ID: "plc", Name: "PLC", Zone: "ot", IPs: []string{"10.1.0.5", "2001:db8:1::5"}},
			{ID: "hmi", Name: "HMI", Zone: "ot"},
		},
		DataPlane: config.DataPlaneConfig{Enforcement: true},
		Firewall:  config.FirewallConfig{DefaultAction: config.ActionDeny},
		Services: config.ServicesConfig{AV: config.AVConfig{Enabled: true, HTTPDownload: true, FailPolicy: "closed", Scan: config.ScanSelection{
			Include: []config.ScanInclude{{SourceZones: []string{"lan"}, DestZones: []string{"void", "wan"}, DestPorts: []string{"8080", "80", "8000-8099", "8100-8110", "81"}}},
		}}},
	}
	mut(cfg)
	return cfg
}

func compileGateSnapshot(t *testing.T, cfg *config.Config) rules.GateSelection {
	t.Helper()
	snap, err := CompileSnapshot(cfg)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	// The snapshot crosses the management-to-engine JSON boundary.
	wire, err := json.Marshal(snap)
	if err != nil {
		t.Fatal(err)
	}
	var received rules.Snapshot
	if err := json.Unmarshal(wire, &received); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(received.Gate, snap.Gate) {
		t.Fatalf("gate changed on the wire:\n%+v\n%+v", snap.Gate, received.Gate)
	}
	return snap.Gate
}

func TestCompileGateResolvesSelection(t *testing.T) {
	got := compileGateSnapshot(t, gateConfig(func(cfg *config.Config) {
		cfg.Services.AV.Scan.Exclude = []config.ScanExclude{
			{Sources: []string{"10.1.2.3/32", "10.0.0.0/8", "10.0.0.0/8"}, Destinations: []string{"192.0.2.0/24", "2001:db8::/32"}},
			{Sources: []string{"2001:db8::/32"}, DestPorts: []string{"443"}},
			{SourceZones: []string{"lan"}, DestZones: []string{"wan"}, DestPorts: []string{"8080"}},
			{SourceZones: []string{"void"}},
			{DestZones: []string{"void"}, DestPorts: []string{"80"}},
		}
		cfg.Services.AV.Scan.ICSZones = []string{"ot", "void"}
		cfg.Services.AV.Scan.ICSAssets = []string{"plc", "hmi"}
	}))
	want := rules.GateSelection{
		Enabled: true,
		Include: []rules.GateEntry{{
			SourceDevices: []string{"eth2", "lan3"},
			DestZones:     []string{"wan"},
			Ports:         []rules.GatePortRange{{Lo: 80, Hi: 81}, {Lo: 8000, Hi: 8110}},
		}},
		Exclude: []rules.GateEntry{
			{Family: 4, Sources: []string{"10.0.0.0/8", "10.1.2.3/32"}, Destinations: []string{"192.0.2.0/24"}},
			{Family: 6, Sources: []string{"2001:db8::/32"}, Ports: []rules.GatePortRange{{Lo: 443, Hi: 443}}},
			{SourceDevices: []string{"eth2", "lan3"}, DestDevices: []string{"eth0"}, Ports: []rules.GatePortRange{{Lo: 8080, Hi: 8080}}},
		},
		Zones:        []rules.GateZone{{Name: "wan", Index: 1, Devices: []string{"eth0"}}, {Name: "void", Index: 2}},
		ICSDevices:   []string{"ot0"},
		ICSCIDRs:     []string{"10.1.0.0/24", "10.1.0.5/32", "2001:db8:1::/64", "2001:db8:1::5/128"},
		FailPolicy:   "closed",
		DownloadMode: "hold",
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("gate selection:\n got %+v\nwant %+v", got, want)
	}
}

func TestCompileGateIndexesEveryZoneForAnyEgress(t *testing.T) {
	got := compileGateSnapshot(t, gateConfig(func(cfg *config.Config) {
		cfg.Services.AV.Scan.Include = []config.ScanInclude{
			{DestZones: []string{"lan"}, DestPorts: []string{"80"}},
			{DestPorts: []string{"8080"}},
		}
		cfg.Services.AV.Scan.DownloadMode = "stream_tail"
	}))
	wantZones := []rules.GateZone{
		{Name: "wan", Index: 1, Devices: []string{"eth0"}},
		{Name: "lan", Index: 2, Devices: []string{"eth2", "lan3"}},
		{Name: "ot", Index: 3, Devices: []string{"ot0"}},
		{Name: "void", Index: 4},
	}
	if !reflect.DeepEqual(got.Zones, wantZones) {
		t.Fatalf("zones = %+v", got.Zones)
	}
	wantInclude := []rules.GateEntry{
		{DestZones: []string{"lan"}, Ports: []rules.GatePortRange{{Lo: 80, Hi: 80}}},
		{DestZones: []string{"wan", "lan", "ot"}, Ports: []rules.GatePortRange{{Lo: 8080, Hi: 8080}}},
	}
	if !reflect.DeepEqual(got.Include, wantInclude) {
		t.Fatalf("include = %+v", got.Include)
	}
	if got.DownloadMode != "stream_tail" || got.FailPolicy != "closed" {
		t.Fatalf("modes = %q %q", got.DownloadMode, got.FailPolicy)
	}
}

func TestCompileGateZoneIndicesAreStable(t *testing.T) {
	first := compileGateSnapshot(t, gateConfig(func(*config.Config) {}))
	// Binding a device to void and appending a zone must not renumber wan.
	second := compileGateSnapshot(t, gateConfig(func(cfg *config.Config) {
		cfg.Zones = append(cfg.Zones, config.Zone{Name: "guest"})
		cfg.Interfaces = append(cfg.Interfaces, config.Interface{Name: "void0", Zone: "void", Device: "eth9"})
		cfg.Services.AV.Scan.Include[0].DestZones = []string{"guest", "wan", "void"}
	}))
	if !reflect.DeepEqual(first.Zones, []rules.GateZone{{Name: "wan", Index: 1, Devices: []string{"eth0"}}, {Name: "void", Index: 2}}) {
		t.Fatalf("zones = %+v", first.Zones)
	}
	if !reflect.DeepEqual(second.Zones, []rules.GateZone{
		{Name: "wan", Index: 1, Devices: []string{"eth0"}},
		{Name: "void", Index: 2, Devices: []string{"eth9"}},
		{Name: "guest", Index: 3},
	}) {
		t.Fatalf("zones renumbered: %+v -> %+v", first.Zones, second.Zones)
	}
	if !reflect.DeepEqual(second.Include[0].DestZones, []string{"wan", "void"}) {
		t.Fatalf("dest zones = %v", second.Include[0].DestZones)
	}
}

func TestCompileGateDropsUnmatchableEntries(t *testing.T) {
	got := compileGateSnapshot(t, gateConfig(func(cfg *config.Config) {
		cfg.Services.AV.Scan.Include = []config.ScanInclude{
			{SourceZones: []string{"void"}, DestPorts: []string{"80"}},
			{DestZones: []string{"void"}, DestPorts: []string{"80"}},
			{SourceZones: []string{"wan"}, DestZones: []string{"lan"}, DestPorts: []string{"80"}},
		}
	}))
	if len(got.Include) != 1 || !reflect.DeepEqual(got.Include[0].SourceDevices, []string{"eth0"}) {
		t.Fatalf("include = %+v", got.Include)
	}
}

func TestCompileGateFollowsEnableRule(t *testing.T) {
	for name, mut := range map[string]func(*config.Config){
		"scanning off":      func(cfg *config.Config) { cfg.Services.AV.Enabled = false },
		"no http direction": func(cfg *config.Config) { cfg.Services.AV.HTTPDownload = false },
		"no include":        func(cfg *config.Config) { cfg.Services.AV.Scan.Include = nil },
	} {
		t.Run(name, func(t *testing.T) {
			got := compileGateSnapshot(t, gateConfig(func(cfg *config.Config) {
				cfg.Services.AV.Scan.Exclude = []config.ScanExclude{{DestPorts: []string{"443"}}}
				cfg.Services.AV.Scan.ICSZones = []string{"ot"}
				mut(cfg)
			}))
			want := rules.GateSelection{FailPolicy: "closed", DownloadMode: "hold"}
			if !reflect.DeepEqual(got, want) {
				t.Fatalf("gate = %+v, want disabled", got)
			}
		})
	}
	got := compileGateSnapshot(t, gateConfig(func(cfg *config.Config) {
		cfg.Services.AV.HTTPDownload, cfg.Services.AV.HTTPUpload = false, true
	}))
	if !got.Enabled || len(got.Include) != 1 {
		t.Fatalf("upload-only gate = %+v", got)
	}
}

func TestCompileSnapshotRejectsDecoderPortSelection(t *testing.T) {
	_, err := CompileSnapshot(gateConfig(func(cfg *config.Config) {
		cfg.Services.AV.Scan.Include[0].DestPorts = []string{"80", "500-600"}
	}))
	if err == nil || !strings.Contains(err.Error(), "modbus/502") {
		t.Fatalf("compile = %v, want the decoder port named", err)
	}
}
