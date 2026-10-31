// SPDX-License-Identifier: Apache-2.0
package config

import (
	"reflect"
	"slices"
	"strings"
	"testing"
)

func placementConfig(kind string) *Config {
	c := DefaultConfig()
	c.DataPlane.DPIMode = "enforce"
	c.DataPlane.NFQueueGroup = 101
	c.Firewall.Rules = []Rule{{
		ID: "reads", Action: ActionAllow, Protocols: []Protocol{{Name: "tcp", Port: "502"}},
		ICS: ICSPredicate{Protocol: "modbus", FunctionCode: []uint8{3}},
	}}
	f := policyForward("process", "")
	f.AllowedSources = []string{"198.51.100.0/24"}
	c.Firewall.NAT.PortForwards = []PortForward{f}
	switch kind {
	case "partial":
		c.Firewall.Rules[0].Sources = []string{"198.51.100.0/25"}
	case "no-overlap":
		c.Firewall.Rules[0].Protocols[0].Port = "503"
	}
	return c
}

func TestForwardPlacementUpgradeAndPublish(t *testing.T) {
	for _, kind := range []string{"inside", "partial", "no-overlap"} {
		for _, path := range []string{"upgrade", "publish"} {
			t.Run(path+"/"+kind, func(t *testing.T) {
				c := placementConfig(kind)
				original := slices.Clone(c.Firewall.Rules)
				f := c.Firewall.NAT.PortForwards[0]
				p := ForwardAllowPlacement(c, f)
				if p.Overlap != kind || (p.Rule != nil) != (kind == "no-overlap") {
					t.Fatalf("placement: %+v", p)
				}
				if !reflect.DeepEqual(original, c.Firewall.Rules) {
					t.Fatal("placement mutated policy")
				}
				if path == "upgrade" {
					c.SchemaVersion = "0.1.9"
					if err := UpgradeInPlace(c); err != nil {
						t.Fatal(err)
					}
					if c.orderMigration == nil || c.orderMigration.Forwards[0].Overlap != kind {
						t.Fatal("upgrade did not use shared placement")
					}
				} else if p.Rule != nil {
					c.Firewall.Rules = slices.Insert(c.Firewall.Rules, p.Index, *p.Rule)
				}
				want := 1
				if kind == "no-overlap" {
					want = 2
					if c.Firewall.Rules[0].ID != "pf-process" {
						t.Fatal("grant is not leading")
					}
				}
				if len(c.Firewall.Rules) != want {
					t.Fatalf("rules: %+v", c.Firewall.Rules)
				}
				// Reads, writes and default semantics stay represented by the
				// original rule: no shadowing grant was inserted in either case.
				if !reflect.DeepEqual(c.Firewall.Rules[len(c.Firewall.Rules)-1], original[0]) {
					t.Fatal("existing ICS policy changed")
				}
				warnings := ForwardWarnings(c)
				if (len(warnings) > 0) != (kind == "partial") {
					t.Fatal(warnings)
				}
				if kind == "partial" {
					w := warnings[0]
					for _, text := range []string{"process", "reads", "198.51.100.0/24", "wan", "tcp", "10.0.0.8:502", "outside the inspected subset", "current policy decides"} {
						if !strings.Contains(w.Message, text) {
							t.Fatalf("warning omits %q: %+v", text, w)
						}
					}
				}
			})
		}
	}
}

func TestForwardPlacementScopeProof(t *testing.T) {
	for name, tc := range map[string]struct {
		edit func(*Config)
		want string
	}{
		"all matching IDs": {func(c *Config) {
			c.Firewall.Rules[0].Sources = []string{"198.51.100.0/25"}
			r := c.Firewall.Rules[0]
			r.ID = "other"
			c.Firewall.Rules = append(c.Firewall.Rules, r)
		}, "partial"},
		"identity":                {func(c *Config) { c.Firewall.Rules[0].Identities = []string{"operator"} }, "partial"},
		"schedule":                {func(c *Config) { c.Firewall.Rules[0].Schedule = &ScheduleConfig{} }, "partial"},
		"unknown routed zone":     {func(c *Config) { c.Firewall.Rules[0].DestZones = []string{"lan"} }, "partial"},
		"unknown token":           {func(c *Config) { c.Firewall.Rules[0].Sources = []string{"vpn:any"} }, "partial"},
		"unknown historical port": {func(c *Config) { c.Firewall.Rules[0].Protocols[0].Port = "bad" }, "partial"},
		"canonical forward transport": {func(c *Config) {
			c.Firewall.NAT.PortForwards[0].Proto = " TCP "
			c.Firewall.NAT.PortForwards[0].IngressZone = " wan "
			c.Firewall.Rules[0].SourceZones = []string{"wan"}
		}, "inside"},
		"public not backend port": {func(c *Config) { c.Firewall.Rules[0].Protocols[0].Port = "1502" }, "no-overlap"},
		"other backend":           {func(c *Config) { c.Firewall.Rules[0].Destinations = []string{"10.0.1.0/24"} }, "no-overlap"},
		"other source":            {func(c *Config) { c.Firewall.Rules[0].Sources = []string{"192.0.2.0/24"} }, "no-overlap"},
		"other ingress":           {func(c *Config) { c.Firewall.Rules[0].SourceZones = []string{"lan"} }, "no-overlap"},
		"other via":               {func(c *Config) { c.Firewall.Rules[0].ViaForwards = []string{"other"} }, "no-overlap"},
		"monitor":                 {func(c *Config) { c.Firewall.Rules[0].ICS.Mode = "monitor" }, "no-overlap"},
		"effect":                  {func(c *Config) { c.Firewall.Rules[0].Action = ActionTag }, "no-overlap"},
		"one full scope suffices": {func(c *Config) {
			r := c.Firewall.Rules[0]
			r.ID, r.Sources = "partial", []string{"198.51.100.0/25"}
			c.Firewall.Rules = append(c.Firewall.Rules, r)
		}, "inside"},
	} {
		t.Run(name, func(t *testing.T) {
			c := placementConfig("inside")
			tc.edit(c)
			p := ForwardAllowPlacement(c, c.Firewall.NAT.PortForwards[0])
			if p.Overlap != tc.want {
				t.Fatalf("%+v, want %s", p, tc.want)
			}
			if name == "all matching IDs" && !reflect.DeepEqual(p.RuleIDs, []string{"other", "reads"}) {
				t.Fatal("missing overlapping scope", p)
			}
		})
	}
}

func TestForwardMigrationStableGrantsAndOperatorControl(t *testing.T) {
	c := placementConfig("no-overlap")
	c.SchemaVersion = ""
	a, z := policyForward("a", ""), policyForward("z", "203.0.113.8")
	a.ListenPort, z.ListenPort = 2502, 3502
	z.Enabled = false
	c.Firewall.NAT.PortForwards = append(c.Firewall.NAT.PortForwards, z, a)
	c.Firewall.Rules = append(c.Firewall.Rules, Rule{ID: "pf-a", Action: ActionDeny})
	if err := UpgradeInPlace(c); err != nil {
		t.Fatal(err)
	}
	if got := policyRuleIDs(c); !reflect.DeepEqual(got, []string{"pf-a-1", "pf-process", "pf-z", "reads", "pf-a"}) {
		t.Fatal(got)
	}
	if c.orderMigration.SchemaBefore != "" || c.SchemaVersion != "0.1.10" {
		t.Fatal("eligibility lost")
	}
	c.Firewall.Rules = []Rule{{ID: "operator-deny", Action: ActionDeny}, c.Firewall.Rules[1]}
	before := slices.Clone(c.Firewall.Rules)
	if err := UpgradeInPlace(c); err != nil || !reflect.DeepEqual(before, c.Firewall.Rules) {
		t.Fatal("current schema regenerated or reordered", err)
	}
	// Existing references, whatever their action, suppress duplicate grants.
	c.SchemaVersion = "0.1.9"
	c.Firewall.Rules = []Rule{{ID: "explicit-deny", Action: ActionDeny, ViaForwards: []string{"process", "a", "z"}}}
	if err := UpgradeInPlace(c); err != nil || len(c.Firewall.Rules) != 1 {
		t.Fatal("existing references ignored", err)
	}
}

func TestOrderedForwardMigrationCorpus(t *testing.T) {
	c := placementConfig("partial")
	c.SchemaVersion = "0.1.9"
	inside := c.Firewall.NAT.PortForwards[0]
	inside.ID, inside.ListenPort, inside.AllowedSources = "inside-process", 2502, []string{"198.51.100.0/26"}
	partial := c.Firewall.NAT.PortForwards[0]
	partial.ID = "partial-process"
	outside := c.Firewall.NAT.PortForwards[0]
	outside.ID, outside.ListenPort, outside.DestPort = "outside-process", 3502, 503
	c.Firewall.NAT.PortForwards = []PortForward{outside, partial, inside}
	if err := c.Validate(); err != nil {
		t.Fatal(err)
	}
	counts := map[string]int{}
	var partialIDs []string
	for _, p := range c.orderMigration.Forwards {
		counts[p.Overlap]++
		if p.Overlap == "partial" {
			partialIDs = append(partialIDs, p.ForwardID)
		}
	}
	if !reflect.DeepEqual(counts, map[string]int{"inside": 1, "partial": 1, "no-overlap": 1}) ||
		!reflect.DeepEqual(partialIDs, []string{"partial-process"}) ||
		!reflect.DeepEqual(policyRuleIDs(c), []string{"pf-outside-process", "reads"}) {
		t.Fatal("one conflicted forward affected another", counts, partialIDs, policyRuleIDs(c))
	}
	t.Logf("forward migration corpus: inside=%d partial=%d no-overlap=%d; partial IDs=%v (synthetic)",
		counts["inside"], counts["partial"], counts["no-overlap"], partialIDs)
}
