// SPDX-License-Identifier: Apache-2.0
package config

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"
)

func policyForward(id, listen string) PortForward {
	return PortForward{ID: id, Enabled: true, IngressZone: "wan", Proto: "tcp", ListenAddress: listen, ListenPort: 1502, DestIP: "10.0.0.8", DestPort: 502}
}

func TestForwardListenAddressOverlap(t *testing.T) {
	for _, tc := range []struct {
		first, second string
		overlap       bool
	}{
		{"", "", true}, {"203.0.113.1", "203.0.113.1", true},
		{"203.0.113.1", "203.0.113.2", false}, {"", "203.0.113.1", true}, {"203.0.113.1", "", true},
	} {
		cfg := DefaultConfig()
		cfg.Firewall.NAT.PortForwards = []PortForward{policyForward("a", tc.first), policyForward("b", tc.second)}
		err := cfg.Validate()
		if (err != nil) != tc.overlap {
			t.Fatalf("listen %q/%q overlap=%v: %v", tc.first, tc.second, tc.overlap, err)
		}
		if err != nil && !strings.Contains(err.Error(), "overlaps") {
			t.Fatal(err)
		}
	}
}

func TestValidateForwardListenIPv4(t *testing.T) {
	for _, addr := range []string{"", "203.0.113.1", "2001:db8::1", "::ffff:203.0.113.1", "203.0.113.1/32", "host", " 203.0.113.1"} {
		cfg := DefaultConfig()
		cfg.Firewall.NAT.PortForwards = []PortForward{policyForward("f", addr)}
		err := cfg.Validate()
		if (err == nil) != (addr == "" || addr == "203.0.113.1") {
			t.Fatalf("listen %q: %v", addr, err)
		}
	}
	cfg := DefaultConfig()
	f := policyForward("f", "")
	f.AllowedSources = []string{""}
	cfg.Firewall.NAT.PortForwards = []PortForward{f}
	if err := cfg.Validate(); err == nil {
		t.Fatal("empty source silently became unrestricted")
	}
}

func TestViaForwardReferencesAndStrictJSON(t *testing.T) {
	var rule Rule
	if err := json.Unmarshal([]byte(`{"id":"via","action":"ALLOW","viaForwards":["f","g"]}`), &rule); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(rule.ViaForwards, []string{"f", "g"}) {
		t.Fatal("lost via list")
	}
	for _, disabled := range []bool{false, true} {
		cfg := DefaultConfig()
		f, g := policyForward("f", ""), policyForward("g", "203.0.113.3")
		g.ListenPort = 1503
		f.Enabled = !disabled
		cfg.Firewall.NAT.PortForwards = []PortForward{f, g}
		cfg.Firewall.Rules = []Rule{rule}
		if err := cfg.Validate(); err != nil {
			t.Fatal("disabled reference must remain structurally valid", err)
		}
		cfg.Firewall.NAT.PortForwards = cfg.Firewall.NAT.PortForwards[1:]
		if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), "rule via") || !strings.Contains(err.Error(), `"f"`) {
			t.Fatalf("deleted/renamed referenced forward: %v", err)
		}
	}
}

func TestForwardAllowRuleStableCollisionIDs(t *testing.T) {
	cfg := DefaultConfig()
	for _, id := range []string{"pf-f", "pf-f-1"} {
		cfg.Firewall.Rules = append(cfg.Firewall.Rules, Rule{ID: id, Action: ActionDeny})
	}
	got := ForwardAllowRule(cfg, "f")
	want := Rule{ID: "pf-f-2", Action: ActionAllow, Description: "Allows port forward f", ViaForwards: []string{"f"}, Log: true}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("allow = %+v", got)
	}
	if len(cfg.Firewall.Rules) != 2 {
		t.Fatal("generator mutated policy")
	}
}

func TestForwardCannotOverlapReservedManagement(t *testing.T) {
	for _, listen := range []string{"", "10.99.99.2"} {
		cfg, reservation := reservationFixture()
		f := policyForward("f", listen)
		f.IngressZone, f.ListenPort = "lan", int(reservation.Port)
		cfg.Firewall.NAT.Enabled = false
		cfg.Firewall.NAT.PortForwards = []PortForward{f}
		if err := ValidateManagementReservation(cfg, reservation); err == nil {
			t.Fatal("reserved management DNAT accepted")
		}
	}
}

func TestRejectIPv6RoutingSelectorsRetainFirewallIPv6(t *testing.T) {
	for name, edit := range map[string]func(*Config){
		"interface gateway":  func(c *Config) { c.Interfaces[0].Gateway = "2001:db8::1" },
		"named gateway":      func(c *Config) { c.Routing.Gateways = []Gateway{{Name: "g", Address: "2001:db8::1"}} },
		"route destination":  func(c *Config) { c.Routing.Routes = []StaticRoute{{Dst: "2001:db8::/32"}} },
		"route gateway":      func(c *Config) { c.Routing.Routes = []StaticRoute{{Dst: "default", Gateway: "2001:db8::1"}} },
		"policy source":      func(c *Config) { c.Routing.Rules = []PolicyRule{{Src: "2001:db8::/32", Table: 100}} },
		"policy destination": func(c *Config) { c.Routing.Rules = []PolicyRule{{Dst: "2001:db8::/32", Table: 100}} },
	} {
		t.Run(name, func(t *testing.T) {
			cfg := DefaultConfig()
			edit(cfg)
			if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), "IPv4") {
				t.Fatalf("unsupported IPv6 accepted: %v", err)
			}
		})
	}
	cfg := DefaultConfig()
	cfg.Firewall.Rules = []Rule{{ID: "v6", Action: ActionAllow, Sources: []string{"2001:db8::/32"}, Destinations: []string{"2001:db8:1::/64"}}}
	if err := cfg.Validate(); err != nil {
		t.Fatal("IPv6 firewall support regressed", err)
	}
}
