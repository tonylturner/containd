// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 containd Authors

package config

import "testing"

func TestValidateRuleProtocol(t *testing.T) {
	for _, tc := range []struct {
		name, port string
		valid      bool
	}{
		{"tcp", "", true}, {"udp", "0-65535", true}, {"tcp", "0502", true}, {"icmp", "", true},
		{"sctp", "", false}, {"", "", false}, {"icmp", "8", false}, {"tcp", "65536", false},
		{"tcp", "80-1", false}, {"tcp", "1-2-3", false}, {"tcp", "80 accept", false},
		{"udp", "+80", false}, {"tcp", " 80", false}, {"tcp", "1-", false},
	} {
		t.Run(tc.name+"/"+tc.port, func(t *testing.T) {
			f := FirewallConfig{Rules: []Rule{{ID: "test", Action: ActionAllow, Protocols: []Protocol{{Name: tc.name, Port: tc.port}}}}}
			if err := validateFirewall(f, nil, nil); (err == nil) != tc.valid {
				t.Fatalf("validate = %v, valid=%v", err, tc.valid)
			}
		})
	}
}

func TestValidateCanonicalizesRuleProtocol(t *testing.T) {
	cfg := Config{System: SystemConfig{Hostname: "test"}, Firewall: FirewallConfig{DefaultAction: ActionDeny, Rules: []Rule{{ID: "test", Action: ActionAllow, Protocols: []Protocol{{Name: " TCP ", Port: "502"}, {Name: "UDP"}, {Name: "ICMP"}}}}}}
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
	for i, want := range []string{"tcp", "udp", "icmp"} {
		if got := cfg.Firewall.Rules[0].Protocols[i].Name; got != want {
			t.Fatalf("protocol = %q, want %q", got, want)
		}
	}
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
}
