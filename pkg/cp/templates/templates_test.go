// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

package templates

import (
	"testing"

	"github.com/tonylturner/containd/pkg/cp/config"
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
		"s7comm-read-only",
		"cip-monitor-only",
		"bacnet-read-only",
		"opcua-monitor-only",
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
		"s7comm-read-only",
		"cip-monitor-only",
		"bacnet-read-only",
		"opcua-monitor-only",
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
	if err := ApplyWithOpts("modbus-read-only", cfg, ApplyOpts{Mode: "learn"}); err != nil {
		t.Fatalf("ApplyWithOpts: %v", err)
	}
	for _, r := range cfg.Firewall.Rules {
		if r.ICS.Mode != "learn" {
			t.Errorf("rule %q has Mode:%q after learn override, want learn", r.ID, r.ICS.Mode)
		}
	}
}
