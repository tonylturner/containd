// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

package templates

import (
	"strconv"
	"testing"

	"github.com/tonylturner/containd/pkg/cp/config"
	"github.com/tonylturner/containd/pkg/dp/ics"
)

func TestListReturnsAllTemplates(t *testing.T) {
	all := List()
	if len(all) < 2 {
		t.Fatalf("expected at least 2 templates, got %d", len(all))
	}
	names := map[string]bool{}
	for _, tmpl := range all {
		names[tmpl.Name] = true
	}
	for _, want := range []string{"purdue-baseline", "maintenance-window"} {
		if !names[want] {
			t.Errorf("expected template %q in List() output", want)
		}
	}
}

func TestICSTemplateProtocolPorts(t *testing.T) {
	for _, tc := range []struct {
		name      string
		port      int
		wirePort  string
		ruleCount int
	}{
		{"modbus-read-only", ics.ModbusPort, "502", 2},
		{"dnp3-secure-operations", ics.DNP3Port, "20000", 3},
		{"cip-monitor-only", ics.CIPPort, "44818", 2},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tmpl, err := Get(tc.name)
			if err != nil {
				t.Fatalf("Get(%q): %v", tc.name, err)
			}
			if len(tmpl.Rules) != tc.ruleCount {
				t.Fatalf("rule count=%d, want %d", len(tmpl.Rules), tc.ruleCount)
			}
			for _, rule := range tmpl.Rules {
				if len(rule.Protocols) != 1 {
					t.Fatalf("rule %q protocol list=%v, want one protocol", rule.ID, rule.Protocols)
				}
				protocol := rule.Protocols[0]
				if protocol.Name != "tcp" {
					t.Errorf("rule %q protocol=%q, want tcp", rule.ID, protocol.Name)
				}
				if protocol.Port != tc.wirePort {
					t.Errorf("rule %q wire port=%q, want %q", rule.ID, protocol.Port, tc.wirePort)
				}
				if protocol.Port != strconv.Itoa(tc.port) {
					t.Errorf("rule %q port=%q, want registry port %d", rule.ID, protocol.Port, tc.port)
				}
			}
		})
	}
}

func TestCIPMonitorOnlyUsesAccessClassifier(t *testing.T) {
	rules := CIPMonitorOnly()
	if len(rules) != 2 {
		t.Fatalf("rules=%+v", rules)
	}
	for i, rule := range rules {
		if rule.ICS.Protocol != "cip" || len(rule.ICS.FunctionCode) != 0 || len(rule.ICS.ObjectClasses) != 0 {
			t.Fatalf("rule %d bypasses classifier: %+v", i, rule)
		}
	}
	if rules[0].Action != config.ActionAllow || !rules[0].ICS.ReadOnly || rules[0].ICS.WriteOnly {
		t.Fatalf("read rule=%+v", rules[0])
	}
	if rules[1].Action != config.ActionDeny || !rules[1].ICS.WriteOnly || rules[1].ICS.ReadOnly {
		t.Fatalf("write/control rule=%+v", rules[1])
	}
}

func TestListIsSorted(t *testing.T) {
	all := List()
	for i := 1; i < len(all); i++ {
		if all[i].Name < all[i-1].Name {
			t.Errorf("List() not sorted: %q before %q", all[i-1].Name, all[i].Name)
		}
	}
}

func TestGetReturnsCorrectTemplate(t *testing.T) {
	tmpl, err := Get("purdue-baseline")
	if err != nil {
		t.Fatalf("Get(purdue-baseline): %v", err)
	}
	if tmpl.Name != "purdue-baseline" {
		t.Errorf("expected name purdue-baseline, got %q", tmpl.Name)
	}
	if len(tmpl.Rules) == 0 {
		t.Error("purdue-baseline should have rules")
	}
}

func TestGetReturnsErrorForUnknown(t *testing.T) {
	_, err := Get("nonexistent")
	if err == nil {
		t.Fatal("expected error for nonexistent template")
	}
}

func TestApplyMergesRules(t *testing.T) {
	cfg := &config.Config{}
	cfg.Firewall.Rules = []config.Rule{
		{ID: "existing-rule", Action: config.ActionAllow},
	}

	if err := Apply("purdue-baseline", cfg); err != nil {
		t.Fatalf("Apply: %v", err)
	}

	// Should have the existing rule plus all purdue rules.
	if len(cfg.Firewall.Rules) < 2 {
		t.Fatalf("expected more than 1 rule after apply, got %d", len(cfg.Firewall.Rules))
	}
	// First rule should still be the existing one.
	if cfg.Firewall.Rules[0].ID != "existing-rule" {
		t.Error("existing rule should be preserved at its position")
	}
}

func TestApplySkipsDuplicates(t *testing.T) {
	cfg := &config.Config{}
	if err := Apply("purdue-baseline", cfg); err != nil {
		t.Fatalf("first Apply: %v", err)
	}
	count := len(cfg.Firewall.Rules)

	// Apply again — should not duplicate.
	if err := Apply("purdue-baseline", cfg); err != nil {
		t.Fatalf("second Apply: %v", err)
	}
	if len(cfg.Firewall.Rules) != count {
		t.Errorf("expected %d rules after re-apply, got %d", count, len(cfg.Firewall.Rules))
	}
}

func TestApplyErrorForUnknown(t *testing.T) {
	cfg := &config.Config{}
	if err := Apply("nonexistent", cfg); err == nil {
		t.Fatal("expected error for nonexistent template")
	}
}

func TestMaintenanceTemplateHasSchedules(t *testing.T) {
	tmpl, err := Get("maintenance-window")
	if err != nil {
		t.Fatalf("Get(maintenance-window): %v", err)
	}
	for _, r := range tmpl.Rules {
		if r.Schedule == nil {
			t.Errorf("rule %q should have a schedule predicate", r.ID)
		}
	}
}

func TestPurdueTemplateRuleIDs(t *testing.T) {
	tmpl, err := Get("purdue-baseline")
	if err != nil {
		t.Fatalf("Get(purdue-baseline): %v", err)
	}
	ids := map[string]bool{}
	for _, r := range tmpl.Rules {
		if r.ID == "" {
			t.Error("all rules must have a non-empty ID")
		}
		if ids[r.ID] {
			t.Errorf("duplicate rule ID %q", r.ID)
		}
		ids[r.ID] = true
	}
}

func TestICSTemplatesShipWithLogTrue(t *testing.T) {
	// Every ICS protocol template should set Log:true on every rule it
	// produces. Without this, operators in monitor mode (the safe
	// production default) get no visibility into what would have been
	// blocked — defeating the entire purpose of monitor-first deployment.
	icsTemplates := []string{
		"modbus-read-only",
		"dnp3-secure-operations",
		"cip-monitor-only",
	}
	for _, name := range icsTemplates {
		name := name
		t.Run(name, func(t *testing.T) {
			tmpl, err := Get(name)
			if err != nil {
				t.Fatalf("Get(%q): %v", name, err)
			}
			if len(tmpl.Rules) == 0 {
				t.Fatalf("template %q has no rules", name)
			}
			for _, r := range tmpl.Rules {
				if !r.Log {
					t.Errorf("rule %q in %q has Log:false (should be true for monitor visibility)", r.ID, name)
				}
			}
		})
	}
}

func TestICSTemplatesLeaveModeBlank(t *testing.T) {
	// Templates ship with ICSPredicate.Mode blank so rules inherit the
	// global DPIMode at evaluation time. This is the safe-default
	// production behavior — a real OT environment expects monitor-first.
	// Operators promote rules to enforce via the apply-time `mode`
	// parameter (programmatic API, HTTP, or CLI flag) — NOT by editing
	// templates that ship with the firewall.
	icsTemplates := []string{
		"modbus-read-only",
		"dnp3-secure-operations",
		"cip-monitor-only",
	}
	for _, name := range icsTemplates {
		name := name
		t.Run(name, func(t *testing.T) {
			tmpl, _ := Get(name)
			for _, r := range tmpl.Rules {
				if r.ICS.Mode != "" {
					t.Errorf("rule %q in %q has Mode:%q (should be blank — inherit from global)", r.ID, name, r.ICS.Mode)
				}
			}
		})
	}
}

func TestPurdueDenyRulesHaveLogTrue(t *testing.T) {
	// The 4 explicit deny rules in the Purdue baseline template should
	// log so operators see attempted boundary violations. The default-
	// deny catch-all and the allow rules are left untouched.
	tmpl, err := Get("purdue-baseline")
	if err != nil {
		t.Fatalf("Get(purdue-baseline): %v", err)
	}
	expectedLogged := map[string]bool{
		"purdue-block-l4-to-l2": false,
		"purdue-block-l4-to-l1": false,
		"purdue-block-l4-to-l0": false,
		"purdue-block-l5-to-ot": false,
	}
	for _, r := range tmpl.Rules {
		if _, want := expectedLogged[r.ID]; want {
			if !r.Log {
				t.Errorf("rule %q should have Log:true", r.ID)
			}
			expectedLogged[r.ID] = true
		}
	}
	for id, found := range expectedLogged {
		if !found {
			t.Errorf("expected rule %q not in purdue-baseline template", id)
		}
	}
}

func TestApplyWithOptsOverridesMode(t *testing.T) {
	cfg := &config.Config{}
	if err := ApplyWithOpts("modbus-read-only", cfg, ApplyOpts{Mode: "enforce"}); err != nil {
		t.Fatalf("ApplyWithOpts: %v", err)
	}
	if len(cfg.Firewall.Rules) == 0 {
		t.Fatal("no rules applied")
	}
	for _, r := range cfg.Firewall.Rules {
		if r.ICS.Mode != "enforce" {
			t.Errorf("rule %q has Mode:%q after enforce override, want enforce", r.ID, r.ICS.Mode)
		}
	}
}

func TestApplyWithBlankModePreservesTemplate(t *testing.T) {
	// Blank Mode override → rules keep what the template factory set
	// (also blank).
	cfg := &config.Config{}
	if err := ApplyWithOpts("modbus-read-only", cfg, ApplyOpts{}); err != nil {
		t.Fatalf("ApplyWithOpts: %v", err)
	}
	for _, r := range cfg.Firewall.Rules {
		if r.ICS.Mode != "" {
			t.Errorf("rule %q has Mode:%q with blank override, want blank", r.ID, r.ICS.Mode)
		}
	}
}

func TestApplyWithOptsLearnMode(t *testing.T) {
	// Explicit learn override — locks rules to monitor regardless of
	// global setting.
	cfg := &config.Config{}
	if err := ApplyWithOpts("modbus-read-only", cfg, ApplyOpts{Mode: "monitor"}); err != nil {
		t.Fatalf("ApplyWithOpts: %v", err)
	}
	for _, r := range cfg.Firewall.Rules {
		if r.ICS.Mode != "monitor" {
			t.Errorf("rule %q has Mode:%q after learn override, want learn", r.ID, r.ICS.Mode)
		}
	}
}
