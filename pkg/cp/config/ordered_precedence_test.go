// SPDX-License-Identifier: Apache-2.0
package config

import (
	"reflect"
	"testing"
)

func TestOrderedUpgradePreservesIndependentAuthoredOrder(t *testing.T) {
	for name, tc := range map[string]struct {
		a, b Rule
	}{
		"source zones":      {Rule{SourceZones: []string{"wan"}}, Rule{SourceZones: []string{"lan"}}},
		"destination zones": {Rule{DestZones: []string{"wan"}}, Rule{DestZones: []string{"lan"}}},
		"protocol":          {Rule{Protocols: []Protocol{{Name: "tcp"}}}, Rule{Protocols: []Protocol{{Name: "udp"}}}},
		"ports":             {Rule{Protocols: []Protocol{{Name: "tcp", Port: "1-501"}}}, Rule{Protocols: []Protocol{{Name: "tcp", Port: "502-1000"}}}},
		"sources":           {Rule{Sources: []string{"198.51.100.0/25"}}, Rule{Sources: []string{"198.51.100.128/25"}}},
		"destinations":      {Rule{Destinations: []string{"10.0.0.0/24"}}, Rule{Destinations: []string{"10.0.1.0/24"}}},
		"address families":  {Rule{Sources: []string{"10.0.0.0/8"}}, Rule{Sources: []string{"2001:db8::/32"}}},
		"via selectors":     {Rule{ViaForwards: []string{"first"}}, Rule{ViaForwards: []string{"second"}}},
	} {
		t.Run(name, func(t *testing.T) {
			c := DefaultConfig()
			c.SchemaVersion = "0.1.9"
			a, b := tc.a, tc.b
			// Reverse both the old action precedence and ID order. A disjoint
			// pair needs neither constraint and must retain its authored order.
			a.ID, a.Action = "z-deny", ActionDeny
			b.ID, b.Action = "a-allow", ActionAllow
			c.Firewall.Rules = []Rule{a, {ID: "effect", Action: ActionTag, Tag: "site"}, b}
			if name == "via selectors" {
				first, second := policyForward("first", ""), policyForward("second", "")
				second.ListenPort++
				c.Firewall.NAT.PortForwards = []PortForward{first, second}
			}
			before := policyRuleIDs(c)
			if err := UpgradeInPlace(c); err != nil {
				t.Fatal(err)
			}
			if got := policyRuleIDs(c); !reflect.DeepEqual(got, before) ||
				!reflect.DeepEqual(c.orderMigration.Before, before) || !reflect.DeepEqual(c.orderMigration.After, got) {
				t.Fatalf("independent order/audit changed: %+v", c.orderMigration)
			}
		})
	}
}

func TestOrderedUpgradeConstrainsOverlappingTerminals(t *testing.T) {
	for name, tc := range map[string]struct {
		a, b Rule
	}{
		"wildcards":                           {},
		"shared zone":                         {Rule{SourceZones: []string{"wan", "lan"}}, Rule{SourceZones: []string{"lan"}}},
		"overlapping ports":                   {Rule{Protocols: []Protocol{{Name: "tcp", Port: "1-502"}}}, Rule{Protocols: []Protocol{{Name: "tcp", Port: "502-1000"}}}},
		"protocol union":                      {Rule{Protocols: []Protocol{{Name: "udp"}, {Name: "tcp"}}}, Rule{Protocols: []Protocol{{Name: "tcp"}}}},
		"overlapping CIDRs":                   {Rule{Sources: []string{"198.51.100.0/24"}}, Rule{Sources: []string{"198.51.100.0/25"}}},
		"CIDR union":                          {Rule{Sources: []string{"192.0.2.0/24", "198.51.100.0/24"}}, Rule{Sources: []string{"198.51.100.0/25"}}},
		"mapped IPv4":                         {Rule{Sources: []string{"::ffff:198.51.100.0/120"}}, Rule{Sources: []string{"198.51.100.0/24"}}},
		"unresolved token":                    {Rule{Sources: []string{"vpn:any"}}, Rule{Sources: []string{"198.51.100.0/24"}}},
		"unresolved forward":                  {Rule{ViaForwards: []string{"missing"}}, Rule{ViaForwards: []string{"other"}}},
		"unknown protocol":                    {Rule{Protocols: []Protocol{{Name: "unknown"}}}, Rule{Protocols: []Protocol{{Name: "tcp"}}}},
		"malformed port":                      {Rule{Protocols: []Protocol{{Name: "tcp", Port: "bad"}}}, Rule{Protocols: []Protocol{{Name: "tcp", Port: "502"}}}},
		"same action winner":                  {Rule{Action: ActionAllow}, Rule{Action: ActionAllow}},
		"different forward IDs same selector": {Rule{ViaForwards: []string{"first"}}, Rule{ViaForwards: []string{"second"}}},
	} {
		t.Run(name, func(t *testing.T) {
			c := DefaultConfig()
			c.SchemaVersion = "0.1.9"
			a, b := tc.a, tc.b
			a.ID, b.ID = "z", "a"
			if a.Action == "" {
				a.Action = ActionDeny
			}
			if b.Action == "" {
				b.Action = ActionAllow
			}
			c.Firewall.Rules = []Rule{a, {ID: "effect", Action: ActionTag, Tag: "site"}, b}
			if name == "different forward IDs same selector" {
				c.Firewall.NAT.PortForwards = []PortForward{policyForward("first", ""), policyForward("second", "")}
			}
			if err := UpgradeInPlace(c); err != nil {
				t.Fatal(err)
			}
			want := []string{"a", "effect", "z"}
			if got := policyRuleIDs(c); !reflect.DeepEqual(got, want) ||
				!reflect.DeepEqual(c.orderMigration.Before, []string{"z", "effect", "a"}) ||
				!reflect.DeepEqual(c.orderMigration.After, want) {
				t.Fatalf("legacy precedence/audit lost: %+v", c.orderMigration)
			}
		})
	}
}

func TestOrderedUpgradeUsesAuthoredTopologicalTiebreak(t *testing.T) {
	c := DefaultConfig()
	c.SchemaVersion = "0.1.9"
	c.Firewall.Rules = []Rule{
		{ID: "deny", Action: ActionDeny, SourceZones: []string{"wan"}},
		{ID: "independent", Action: ActionAllow, SourceZones: []string{"lan"}},
		{ID: "allow", Action: ActionAllow, SourceZones: []string{"wan"}},
	}
	if err := UpgradeInPlace(c); err != nil {
		t.Fatal(err)
	}
	if got := policyRuleIDs(c); !reflect.DeepEqual(got, []string{"independent", "allow", "deny"}) {
		t.Fatal("authored ready vertex was not selected first", got)
	}
}
