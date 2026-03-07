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
