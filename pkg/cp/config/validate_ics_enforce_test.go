// SPDX-License-Identifier: Apache-2.0

package config

import (
	"context"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

// genericICSConfig returns a config with one Modbus-style rule of protocol
// proto and rule mode mode, under the given global mode and queue.
func genericICSConfig(proto, mode, global string, queue uint16) *Config {
	return &Config{SchemaVersion: SchemaVersionCurrent,
		System: SystemConfig{Hostname: "containd"},
		Zones:  []Zone{{Name: "lan"}, {Name: "wan"}},
		DataPlane: DataPlaneConfig{
			Enforcement:  true,
			DPIEnabled:   true,
			DPIMode:      global,
			NFQueueGroup: queue,
		},
		Firewall: FirewallConfig{DefaultAction: ActionDeny, Rules: []Rule{{
			ID:           "ics-1",
			SourceZones:  []string{"lan"},
			DestZones:    []string{"wan"},
			Sources:      []string{"10.0.0.5/32"},
			Destinations: []string{"10.1.0.4/32"},
			Protocols:    []Protocol{{Name: "tcp", Port: "502"}},
			ICS:          ICSPredicate{Protocol: proto, FunctionCode: []uint8{3}, Mode: mode},
			Action:       ActionAllow,
		}}},
	}
}

// A rule naming an ICS protocol in effective enforce mode needs NFQUEUE;
// every other combination of rule and global mode is valid without it.
func TestValidateICSEnforceNeedsInlinePath(t *testing.T) {
	generic := []string{"modbus", "dnp3", "cip"}
	modes := []string{"", "monitor", "enforce"}
	for _, proto := range generic {
		for _, rule := range modes {
			for _, global := range modes {
				enforce := rule == "enforce" || (rule == "" && global == "enforce")
				for _, queue := range []uint16{0, 101} {
					err := genericICSConfig(proto, rule, global, queue).Validate()
					name := proto + " rule=" + rule + " global=" + global
					switch {
					case enforce && queue == 0:
						if err == nil || !strings.Contains(err.Error(), "rule ics-1") ||
							!strings.Contains(err.Error(), "dataplane.nfqueueGroup") || !strings.Contains(err.Error(), "ics.mode to monitor") {
							t.Errorf("%s queue 0: err = %v, want a refusal naming the rule and the fix", name, err)
						}
					case err != nil:
						t.Errorf("%s queue %d: unexpected error %v", name, queue, err)
					}
				}
			}
		}
	}
}

func TestValidateICSEnforceIEC104KeepsItsRules(t *testing.T) {
	cfg := iec104Config(iecRule("cc-rtu", ActionAllow, ICSPredicate{ReadOnly: true}))
	cfg.DataPlane.NFQueueGroup = 0
	wantValidateError(t, cfg, "iec104 enforce needs NFQUEUE capture")
}

// These are legal without a refusal; coverage reports what they lack.
func TestValidateICSEnforceLegalWithoutRefusal(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(*Config)
	}{

		{"explicit learn under global enforce", func(c *Config) {
			c.DataPlane.NFQueueGroup = 0
			c.Firewall.Rules[0].ICS.Mode = "monitor"
		}},
		{"nft enforcement off", func(c *Config) { c.DataPlane.Enforcement = false }},
		{"DPI master off", func(c *Config) { c.DataPlane.DPIEnabled = false }},
		{"decoder off", func(c *Config) { c.DataPlane.DPIICSProtocols = map[string]bool{"modbus": false} }},
		{"overlapping and domain exclusions", func(c *Config) {
			c.DataPlane.DPIExclusions = []DPIExclusion{
				{Value: "10.0.0.5", Type: "ip"}, {Value: "*.example.com", Type: "domain"},
			}
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := genericICSConfig("modbus", "", "enforce", 101)
			tc.mutate(cfg)
			if err := cfg.Validate(); err != nil {
				t.Fatalf("rejected: %v", err)
			}
		})
	}
}

// An L4-only IEC 104 policy under global enforce with DPI off (the shape of
// a lab that steers TCP/2404 without semantic rules) stays valid with or
// without a queue: a global mode alone requires nothing.
func TestValidateGlobalEnforceWithoutSemanticRules(t *testing.T) {
	for _, queue := range []uint16{0, 101} {
		cfg := &Config{
			System: SystemConfig{Hostname: "containd"},
			Zones:  []Zone{{Name: "control"}, {Name: "substation"}},
			DataPlane: DataPlaneConfig{
				Enforcement: true, DPIEnabled: false, DPIMode: "enforce", NFQueueGroup: queue, NFLogGroup: 100,
			},
			Firewall: FirewallConfig{DefaultAction: ActionDeny, Rules: []Rule{
				{ID: "iec104-allow", SourceZones: []string{"control"}, DestZones: []string{"substation"},
					Sources: []string{"10.60.60.10/32"}, Destinations: []string{"10.30.30.30/32"},
					Protocols: []Protocol{{Name: "tcp", Port: "2404"}}, Action: ActionAllow},
				{ID: "iec104-deny-others", DestZones: []string{"substation"},
					Protocols: []Protocol{{Name: "tcp", Port: "2404"}}, Action: ActionDeny},
			}},
		}
		if err := cfg.Validate(); err != nil {
			t.Fatalf("queue %d: L4-only global enforce rejected: %v", queue, err)
		}
	}
}

func TestValidateDPIModeEnum(t *testing.T) {
	for _, mode := range []string{"observe", "Enforce", "LEARN", " learn"} {
		cfg := genericICSConfig("modbus", "monitor", mode, 0)
		wantValidateError(t, cfg, "dataplane.dpiMode invalid")
	}
	for _, mode := range []string{"", "monitor", "enforce"} {
		if err := genericICSConfig("modbus", "monitor", mode, 0).Validate(); err != nil {
			t.Fatalf("dpiMode %q rejected: %v", mode, err)
		}
	}
}

// Candidate save, commit and import write through the store, which refuses
// the config and keeps the running revision.
func TestStoreRejectsICSEnforceWithoutInlinePath(t *testing.T) {
	store, err := NewSQLiteStore(filepath.Join(t.TempDir(), "cfg.db"))
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer store.Close()
	ctx := context.Background()
	running := genericICSConfig("modbus", "monitor", "enforce", 0)
	if err := store.Save(ctx, running); err != nil {
		t.Fatalf("save learn config: %v", err)
	}
	before, err := store.Load(ctx)
	if err != nil {
		t.Fatal(err)
	}
	bad := genericICSConfig("modbus", "enforce", "", 0)
	if err := store.SaveCandidate(ctx, bad); err == nil || !strings.Contains(err.Error(), "nfqueueGroup") {
		t.Fatalf("SaveCandidate err = %v, want inline-path refusal", err)
	}
	if err := store.Save(ctx, bad); err == nil || !strings.Contains(err.Error(), "nfqueueGroup") {
		t.Fatalf("Save err = %v, want inline-path refusal", err)
	}
	after, err := store.Load(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(before.Firewall.Rules, after.Firewall.Rules) || after.Firewall.Rules[0].ICS.Mode != "monitor" {
		t.Fatalf("running config changed after a refused save: %+v", after.Firewall.Rules)
	}
}
