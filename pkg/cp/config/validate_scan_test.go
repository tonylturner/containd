// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 containd Authors

package config

import (
	"fmt"
	"strings"
	"testing"
)

// scanConfig is an enforcing default config (zones wan, dmz, lan, mgmt with
// interfaces) plus an interface-less zone "ot", an addressed PLC asset and an
// address-less HMI asset, scanning lan->wan downloads on port 80.
func scanConfig(mut func(*Config)) *Config {
	cfg := DefaultConfig()
	cfg.DataPlane.Enforcement = true
	cfg.Zones = append(cfg.Zones, Zone{Name: "ot"})
	cfg.Assets = []Asset{
		{ID: "plc", Name: "PLC", Zone: "ot", IPs: []string{"10.1.0.5"}},
		{ID: "hmi", Name: "HMI", Zone: "ot"},
	}
	cfg.Services.AV = AVConfig{Enabled: true, HTTPDownload: true, Scan: ScanSelection{
		Include: []ScanInclude{{SourceZones: []string{"lan"}, DestZones: []string{"wan"}, DestPorts: []string{"80"}}},
	}}
	mut(cfg)
	return cfg
}

func TestValidateScanSelectionErrors(t *testing.T) {
	for _, tc := range []struct {
		name string
		mut  func(*Config)
		err  string
	}{
		{"unknown source zone", func(c *Config) { c.Services.AV.Scan.Include[0].SourceZones = []string{"nope"} }, `include[0].sourceZones: unknown zone "nope"`},
		{"unknown dest zone", func(c *Config) { c.Services.AV.Scan.Include[0].DestZones = []string{"nope"} }, `include[0].destZones: unknown zone "nope"`},
		{"unknown exclude zone", func(c *Config) { c.Services.AV.Scan.Exclude = []ScanExclude{{DestZones: []string{"nope"}}} }, `exclude[0].destZones: unknown zone "nope"`},
		{"unknown ics zone", func(c *Config) { c.Services.AV.Scan.ICSZones = []string{"nope"} }, `icsZones: unknown zone "nope"`},
		{"unknown ics asset", func(c *Config) { c.Services.AV.Scan.ICSAssets = []string{"nope"} }, `icsAssets: unknown asset "nope"`},
		{"include needs a port", func(c *Config) { c.Services.AV.Scan.Include[0].DestPorts = nil }, "include[0].destPorts must list at least one port"},
		{"port syntax", func(c *Config) { c.Services.AV.Scan.Include[0].DestPorts = []string{"http"} }, `include[0].destPorts: invalid decimal port "http"`},
		{"nft port syntax", func(c *Config) { c.Services.AV.Scan.Include[0].DestPorts = []string{"{80,8080}"} }, "include[0].destPorts: invalid decimal port"},
		{"port range reversed", func(c *Config) { c.Services.AV.Scan.Include[0].DestPorts = []string{"8080-80"} }, `include[0].destPorts: reversed port range "8080-80"`},
		{"port zero", func(c *Config) { c.Services.AV.Scan.Include[0].DestPorts = []string{"0"} }, `include[0].destPorts: port "0": ports start at 1`},
		{"port too large", func(c *Config) { c.Services.AV.Scan.Include[0].DestPorts = []string{"65536"} }, "include[0].destPorts:"},
		{"exclude port syntax", func(c *Config) { c.Services.AV.Scan.Exclude = []ScanExclude{{DestPorts: []string{"80-"}}} }, "exclude[0].destPorts:"},
		{"modbus port", func(c *Config) { c.Services.AV.Scan.Include[0].DestPorts = []string{"80", "502"} }, `include[0].destPorts "502" covers ICS decoder port modbus/502`},
		{"range covering modbus", func(c *Config) { c.Services.AV.Scan.Include[0].DestPorts = []string{"500-600"} }, `include[0].destPorts "500-600" covers ICS decoder port modbus/502`},
		{"cip port", func(c *Config) { c.Services.AV.Scan.Include[0].DestPorts = []string{"2222"} }, "covers ICS decoder port cip/2222"},
		{"iec104 port", func(c *Config) { c.Services.AV.Scan.Include[0].DestPorts = []string{"2404"} }, "covers ICS decoder port iec104/2404"},
		{"dnp3 port", func(c *Config) { c.Services.AV.Scan.Include[0].DestPorts = []string{"20000"} }, "covers ICS decoder port dnp3/20000"},
		{"ethernet/ip port", func(c *Config) { c.Services.AV.Scan.Include[0].DestPorts = []string{"44818"} }, "covers ICS decoder port cip/44818"},
		{"decoder port in a second entry", func(c *Config) {
			c.Services.AV.Scan.Include = append(c.Services.AV.Scan.Include, ScanInclude{DestPorts: []string{"8080", "40000-50000"}})
		}, `include[1].destPorts "40000-50000" covers ICS decoder port cip/44818`},
		{"enforcement off", func(c *Config) { c.DataPlane.Enforcement = false }, "include needs dataplane.enforcement"},
		{"exclude needs a field", func(c *Config) { c.Services.AV.Scan.Exclude = []ScanExclude{{}} }, "exclude[0] must set at least one of"},
		{"exclude source cidr", func(c *Config) { c.Services.AV.Scan.Exclude = []ScanExclude{{Sources: []string{"10.0.0.1"}}} }, `exclude[0].sources: invalid CIDR "10.0.0.1"`},
		{"exclude destination cidr", func(c *Config) {
			c.Services.AV.Scan.Exclude = []ScanExclude{{Destinations: []string{"fe80::1%eth0/64"}}}
		}, `exclude[0].destinations: invalid CIDR`},
		{"download mode", func(c *Config) { c.Services.AV.Scan.DownloadMode = "stream" }, "downloadMode must be hold or stream_tail"},
		{"too many egress zones", func(c *Config) {
			for i := range 256 {
				c.Zones = append(c.Zones, Zone{Name: fmt.Sprintf("z%03d", i)})
			}
			c.Services.AV.Scan.Include[0].DestZones = nil
		}, "references 261 egress zones; at most 255 zones can be selected"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := scanConfig(tc.mut)
			_, err := ValidateScanSelection(cfg)
			if err == nil || !strings.Contains(err.Error(), tc.err) {
				t.Fatalf("ValidateScanSelection = %v, want error containing %q", err, tc.err)
			}
			if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), tc.err) {
				t.Fatalf("Config.Validate = %v, want error containing %q", err, tc.err)
			}
		})
	}
}

func TestValidateScanSelectionAccepts(t *testing.T) {
	for _, tc := range []struct {
		name string
		mut  func(*Config)
	}{
		{"default", func(*Config) {}},
		{"no selection", func(c *Config) { c.Services.AV.Scan = ScanSelection{} }},
		{"no selection without enforcement", func(c *Config) { c.Services.AV.Scan = ScanSelection{}; c.DataPlane.Enforcement = false }},
		{"scanning disabled keeps the selection", func(c *Config) { c.Services.AV.Enabled = false }},
		{"any zones with ranges", func(c *Config) {
			c.Services.AV.Scan.Include[0] = ScanInclude{DestPorts: []string{" 80 ", "8000-8099", "503-2221"}}
		}},
		{"255 egress zones", func(c *Config) {
			for i := range 250 {
				c.Zones = append(c.Zones, Zone{Name: fmt.Sprintf("z%03d", i)})
			}
			c.Services.AV.Scan.Include[0].DestZones = nil
		}},
		{"exclusions", func(c *Config) {
			c.Services.AV.Scan.Exclude = []ScanExclude{
				{Sources: []string{"10.0.0.0/8", "2001:db8::/32"}, Destinations: []string{"192.0.2.0/24"}},
				{SourceZones: []string{"lan"}, DestZones: []string{"wan"}, DestPorts: []string{"8080-8090"}},
			}
		}},
		{"ics marks", func(c *Config) {
			c.Services.AV.FailPolicy = "closed"
			c.Services.AV.Scan.ICSZones = []string{"dmz"}
			c.Services.AV.Scan.ICSAssets = []string{"plc"}
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := scanConfig(tc.mut)
			warnings, err := ValidateScanSelection(cfg)
			if err != nil || len(warnings) != 0 {
				t.Fatalf("ValidateScanSelection = %v, %v; want valid without warnings", warnings, err)
			}
			if err := cfg.Validate(); err != nil {
				t.Fatalf("Config.Validate: %v", err)
			}
		})
	}
}

func TestValidateScanSelectionWarnings(t *testing.T) {
	for _, tc := range []struct {
		name string
		mut  func(*Config)
		want []string
	}{
		{"zone without interface, once", func(c *Config) {
			c.Services.AV.Scan.Include[0].DestZones = []string{"wan", "ot"}
			c.Services.AV.Scan.Exclude = []ScanExclude{{SourceZones: []string{"ot"}}}
			c.Services.AV.Scan.ICSZones = []string{"ot"}
		}, []string{`services.av.scan.include[0].destZones: zone "ot" has no interface bound to it, so it selects no traffic`}},
		{"asset without address", func(c *Config) { c.Services.AV.Scan.ICSAssets = []string{"plc", "hmi"} },
			[]string{`services.av.scan.icsAssets: asset "hmi" has no IP address, so it marks no endpoint`}},
		{"fail closed without ics marks", func(c *Config) { c.Services.AV.FailPolicy = "closed" },
			[]string{"services.av.scan: failPolicy is closed with no icsZones or icsAssets; no endpoint passes unscanned content while the scanner is unavailable"}},
		{"fail closed without a selection", func(c *Config) { c.Services.AV.FailPolicy = "closed"; c.Services.AV.Scan.Include = nil }, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := scanConfig(tc.mut)
			warnings, err := ValidateScanSelection(cfg)
			if err != nil {
				t.Fatal(err)
			}
			if strings.Join(warnings, "\n") != strings.Join(tc.want, "\n") {
				t.Fatalf("warnings = %q, want %q", warnings, tc.want)
			}
		})
	}
}

func TestScanPortRangeAndCIDR(t *testing.T) {
	if lo, hi, err := ScanPortRange(" 8000-8099 "); err != nil || lo != 8000 || hi != 8099 {
		t.Fatalf("ScanPortRange = %d-%d, %v", lo, hi, err)
	}
	for _, bad := range []string{"", "0", "0-80", "80-70", "65536", "80,81", "8000-"} {
		if _, _, err := ScanPortRange(bad); err == nil {
			t.Errorf("ScanPortRange(%q) accepted", bad)
		}
	}
	if p, err := ScanCIDR(" 10.1.2.3/8 "); err != nil || p.String() != "10.0.0.0/8" {
		t.Fatalf("ScanCIDR = %s, %v; want the masked prefix", p, err)
	}
	if p, err := ScanCIDR("::ffff:192.0.2.1/128"); err != nil || p.String() != "192.0.2.1/32" {
		t.Fatalf("ScanCIDR = %s, %v; want an unmapped prefix", p, err)
	}
	for _, bad := range []string{"", "10.0.0.1", "10.0.0.0/33", "fe80::1%eth0/64", "example.com/24", "::ffff:0.0.0.0/64"} {
		if _, err := ScanCIDR(bad); err == nil {
			t.Errorf("ScanCIDR(%q) accepted", bad)
		}
	}
}

func TestZoneDevices(t *testing.T) {
	got := ZoneDevices([]Interface{
		{Name: "lan2", Zone: "lan", Device: "eth2"},
		{Name: "lan1", Zone: "lan"},
		{Name: "wan", Zone: "wan", Device: " eth0 "},
		{Name: "spare"},
	})
	if len(got) != 2 || strings.Join(got["lan"], ",") != "eth2,lan1" || strings.Join(got["wan"], ",") != " eth0 " {
		t.Fatalf("ZoneDevices = %v", got)
	}
}
