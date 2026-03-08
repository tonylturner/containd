// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

package enforce

import (
	"net"
	"strings"
	"testing"
	"time"

	"github.com/tonylturner/containd/pkg/dp/rules"
)

func TestCompileFirewallBasic(t *testing.T) {
	compiler := NewCompiler()
	snap := &rules.Snapshot{
		Default: rules.ActionDeny,
		Firewall: []rules.Entry{
			{ID: "10", Action: rules.ActionAllow, Protocols: []rules.Protocol{{Name: "tcp", Port: "80"}}},
			{ID: "20", Action: rules.ActionDeny, Sources: []string{"10.0.0.0/8"}},
		},
	}
	ruleset, err := compiler.CompileFirewall(snap)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	if !strings.Contains(ruleset, "table inet containd") {
		t.Fatalf("missing table: %s", ruleset)
	}
	if !strings.Contains(ruleset, "set block_hosts") || !strings.Contains(ruleset, "set block_flows") {
		t.Fatalf("missing dynamic sets")
	}
	if !strings.Contains(ruleset, "policy drop") {
		t.Fatalf("missing default drop policy")
	}
	if !strings.Contains(ruleset, "tcp dport 80 accept") {
		t.Fatalf("missing allow rule: %s", ruleset)
	}
	if !strings.Contains(ruleset, "ip saddr { 10.0.0.0/8 } drop") {
		t.Fatalf("missing deny rule: %s", ruleset)
	}
}

func TestCompileFirewallZoneBindings(t *testing.T) {
	compiler := NewCompiler()
	snap := &rules.Snapshot{
		Default: rules.ActionDeny,
		ZoneIfaces: map[string][]string{
			"wan": {"wan"},
			"lan": {"lan2", "lan3"},
		},
		Firewall: []rules.Entry{
			{
				ID:          "z1",
				SourceZones: []string{"lan"},
				DestZones:   []string{"wan"},
				Protocols:   []rules.Protocol{{Name: "tcp", Port: "80"}},
				Action:      rules.ActionAllow,
			},
		},
	}
	ruleset, err := compiler.CompileFirewall(snap)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	if !strings.Contains(ruleset, "set zone_lan_ifaces") || !strings.Contains(ruleset, "type ifname") {
		t.Fatalf("missing zone iface sets: %s", ruleset)
	}
	if !strings.Contains(ruleset, "iifname { \"lan2\", \"lan3\" }") || !strings.Contains(ruleset, "oifname { \"wan\" }") {
		t.Fatalf("missing iif/oif bindings: %s", ruleset)
	}
}

func TestCompileFirewallQueueRulesForDPIEntries(t *testing.T) {
	compiler := NewCompiler()
	compiler.QueueID = 42

	snap := &rules.Snapshot{
		Default: rules.ActionDeny,
		Firewall: []rules.Entry{
			{
				ID:        "ics1",
				Action:    rules.ActionAllow,
				Protocols: []rules.Protocol{{Name: "tcp", Port: "502"}},
				ICS:       rules.ICSPredicate{Protocol: "modbus"},
			},
			{
				ID:        "web",
				Action:    rules.ActionAllow,
				Protocols: []rules.Protocol{{Name: "tcp", Port: "80"}},
			},
		},
	}
	ruleset, err := compiler.CompileFirewall(snap)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	// The ICS entry should use queue instead of accept.
	if !strings.Contains(ruleset, "tcp dport 502 queue num 42") {
		t.Fatalf("expected queue rule for ICS entry, got:\n%s", ruleset)
	}
	// The non-ICS entry should still use accept.
	if !strings.Contains(ruleset, "tcp dport 80 accept") {
		t.Fatalf("expected accept rule for non-ICS entry, got:\n%s", ruleset)
	}
}

func TestCompileFirewallNoQueueWithoutQueueID(t *testing.T) {
	compiler := NewCompiler()
	// QueueID is 0 (default) — no queue rules should be emitted.
	snap := &rules.Snapshot{
		Default: rules.ActionDeny,
		Firewall: []rules.Entry{
			{
				ID:        "ics1",
				Action:    rules.ActionAllow,
				Protocols: []rules.Protocol{{Name: "tcp", Port: "502"}},
				ICS:       rules.ICSPredicate{Protocol: "modbus"},
			},
		},
	}
	ruleset, err := compiler.CompileFirewall(snap)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	if strings.Contains(ruleset, "queue") {
		t.Fatalf("did not expect queue rule when QueueID is 0, got:\n%s", ruleset)
	}
	if !strings.Contains(ruleset, "tcp dport 502 accept") {
		t.Fatalf("expected accept rule, got:\n%s", ruleset)
	}
}

func TestIsDPIEligible(t *testing.T) {
	tests := []struct {
		name     string
		entry    rules.Entry
		eligible bool
	}{
		{
			name:     "ICS modbus entry",
			entry:    rules.Entry{ICS: rules.ICSPredicate{Protocol: "modbus"}},
			eligible: true,
		},
		{
			name:     "ICS dnp3 entry",
			entry:    rules.Entry{ICS: rules.ICSPredicate{Protocol: "dnp3"}},
			eligible: true,
		},
		{
			name:     "plain rule no ICS",
			entry:    rules.Entry{Action: rules.ActionAllow},
			eligible: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := isDPIEligible(tt.entry); got != tt.eligible {
				t.Fatalf("isDPIEligible() = %v, want %v", got, tt.eligible)
			}
		})
	}
}

func TestNftUpdaterArgsFormatting(t *testing.T) {
	u := NewNftUpdater("containd")
	ip := net.ParseIP("10.1.2.3")
	args := u.buildBlockHostArgs(ip, 5*time.Second)
	joined := strings.Join(args, " ")
	if !strings.Contains(joined, "block_hosts") || !strings.Contains(joined, "10.1.2.3 timeout 5s") {
		t.Fatalf("unexpected host args: %s", joined)
	}

	src := net.ParseIP("10.0.0.1")
	dst := net.ParseIP("10.0.0.2")
	fargs := u.buildBlockFlowArgs(src, dst, "502", 0)
	fjoined := strings.Join(fargs, " ")
	if !strings.Contains(fjoined, "block_flows") || !strings.Contains(fjoined, "10.0.0.1 . 10.0.0.2 . 502") {
		t.Fatalf("unexpected flow args: %s", fjoined)
	}
}
