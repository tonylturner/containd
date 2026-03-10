// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

package ids

import (
	"strings"
	"testing"

	"github.com/tonylturner/containd/pkg/cp/config"
)

func TestExportSigmaRoundTrip(t *testing.T) {
	raw := `title: Test Rule
id: test-1
level: high
detection:
  selection:
    function_code: 5
  condition: selection
`
	rule := config.IDSRule{
		ID:           "test-1",
		SourceFormat: "sigma",
		RawSource:    raw,
	}
	out, err := ExportSigmaRule(rule)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if string(out) != raw {
		t.Errorf("round-trip mismatch: got %q", string(out))
	}
}

func TestExportSigmaFromFields(t *testing.T) {
	rule := config.IDSRule{
		ID:          "sigma-test",
		Title:       "Test Detection",
		Description: "Detects test activity",
		Proto:       "modbus",
		Kind:        "request",
		Severity:    "high",
		When: config.IDSCondition{
			Field: "attr.function_code",
			Op:    "in",
			Value: []any{5, 6},
		},
		Labels: map[string]string{},
	}
	out, err := ExportSigmaRule(rule)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	s := string(out)
	if !strings.Contains(s, "title: Test Detection") {
		t.Errorf("missing title in output: %s", s)
	}
	if !strings.Contains(s, "level: high") {
		t.Errorf("missing level in output: %s", s)
	}
	if !strings.Contains(s, "containd.proto.modbus") {
		t.Errorf("missing proto tag in output: %s", s)
	}
}

func TestExportSigmaMultipleRules(t *testing.T) {
	rules := []config.IDSRule{
		{ID: "r1", Title: "Rule One", Labels: map[string]string{}},
		{ID: "r2", Title: "Rule Two", Labels: map[string]string{}},
	}
	out, err := ExportSigmaRules(rules)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(string(out), "---") {
		t.Error("expected document separator in multi-rule output")
	}
}

func TestExportSuricataRoundTrip(t *testing.T) {
	raw := `alert tcp any any -> any 502 (msg:"Modbus Write"; content:"|00 05|"; sid:1000001; rev:1;)`
	rule := config.IDSRule{
		ID:           "suricata-1000001",
		SourceFormat: "suricata",
		RawSource:    raw,
	}
	out, err := ExportSuricataRule(rule)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if out != raw {
		t.Errorf("round-trip mismatch: got %q", out)
	}
}

func TestExportSuricataFromFields(t *testing.T) {
	rule := config.IDSRule{
		ID:       "suricata-2000001",
		Title:    "Test Alert",
		Proto:    "tcp",
		Action:   "alert",
		SrcAddr:  "10.0.0.0/8",
		SrcPort:  "any",
		DstAddr:  "192.168.1.0/24",
		DstPort:  "502",
		Severity: "high",
		ContentMatches: []config.ContentMatch{
			{Pattern: "malicious", Nocase: true},
			{Pattern: "DE AD", IsHex: true},
		},
		References: []string{"https://example.com"},
		Labels:     map[string]string{},
	}
	out, err := ExportSuricataRule(rule)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(out, "alert tcp") {
		t.Errorf("missing action+proto: %s", out)
	}
	if !strings.Contains(out, "10.0.0.0/8") {
		t.Errorf("missing src addr: %s", out)
	}
	if !strings.Contains(out, `msg:"Test Alert"`) {
		t.Errorf("missing msg: %s", out)
	}
	if !strings.Contains(out, `content:"malicious"`) {
		t.Errorf("missing content: %s", out)
	}
	if !strings.Contains(out, "nocase") {
		t.Errorf("missing nocase: %s", out)
	}
	if !strings.Contains(out, "|DE AD|") {
		t.Errorf("missing hex content: %s", out)
	}
	if !strings.Contains(out, "sid:2000001") {
		t.Errorf("missing sid: %s", out)
	}
	if !strings.Contains(out, "priority:2") {
		t.Errorf("missing priority: %s", out)
	}
	if !strings.Contains(out, "reference:url,https://example.com") {
		t.Errorf("missing reference: %s", out)
	}
}

func TestExportSuricataMultipleRules(t *testing.T) {
	rules := []config.IDSRule{
		{ID: "1", Title: "Rule 1", Labels: map[string]string{}},
		{ID: "2", Title: "Rule 2", Labels: map[string]string{}},
	}
	out, err := ExportSuricataRules(rules)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	lines := strings.Split(strings.TrimSpace(string(out)), "\n")
	if len(lines) != 2 {
		t.Errorf("expected 2 lines, got %d", len(lines))
	}
}

func TestExportSnortRoundTrip(t *testing.T) {
	raw := `alert tcp any any -> any 80 (msg:"HTTP Test"; sid:100; rev:1;)`
	rule := config.IDSRule{
		ID:           "snort-100",
		SourceFormat: "snort",
		RawSource:    raw,
	}
	out, err := ExportSnortRule(rule)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if out != raw {
		t.Errorf("round-trip mismatch: got %q", out)
	}
}

func TestExportSnortFromFields(t *testing.T) {
	rule := config.IDSRule{
		ID:       "snort-3000001",
		Title:    "Snort Test",
		Proto:    "tcp",
		Severity: "critical",
		ContentMatches: []config.ContentMatch{
			{Pattern: "attack", Depth: 100, Offset: 10},
		},
		Labels: map[string]string{"classtype": "attempted-admin"},
	}
	out, err := ExportSnortRule(rule)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(out, `msg:"Snort Test"`) {
		t.Errorf("missing msg: %s", out)
	}
	if !strings.Contains(out, "depth:100") {
		t.Errorf("missing depth: %s", out)
	}
	if !strings.Contains(out, "offset:10") {
		t.Errorf("missing offset: %s", out)
	}
	if !strings.Contains(out, "priority:1") {
		t.Errorf("missing priority for critical: %s", out)
	}
	if !strings.Contains(out, "classtype:attempted-admin") {
		t.Errorf("missing classtype: %s", out)
	}
}

func TestExportSnortMultipleRules(t *testing.T) {
	rules := []config.IDSRule{
		{ID: "1", Title: "Rule 1", Labels: map[string]string{}},
		{ID: "2", Title: "Rule 2", Labels: map[string]string{}},
	}
	out, err := ExportSnortRules(rules)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	lines := strings.Split(strings.TrimSpace(string(out)), "\n")
	if len(lines) != 2 {
		t.Errorf("expected 2 lines, got %d", len(lines))
	}
}

func TestExportYARARoundTrip(t *testing.T) {
	raw := `rule TestMalware {
    meta:
        description = "Test"
    strings:
        $a = "test"
    condition:
        $a
}`
	rule := config.IDSRule{
		ID:           "yara-testmalware",
		SourceFormat: "yara",
		RawSource:    raw,
	}
	out, err := ExportYARARule(rule)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if out != raw {
		t.Errorf("round-trip mismatch: got %q", out)
	}
}

func TestExportYARAFromFields(t *testing.T) {
	rule := config.IDSRule{
		ID:          "yara-test",
		Title:       "TestExport",
		Description: "Test export description",
		Severity:    "medium",
		Labels: map[string]string{
			"author":         "Tester",
			"yara.tags":      "malware,trojan",
			"yara.condition": "$s1 or $hex1",
		},
		YARAStrings: []config.YARAString{
			{Name: "$s1", Pattern: "evil", Type: "text", Nocase: true},
			{Name: "$hex1", Pattern: "CA FE BA BE", Type: "hex"},
			{Name: "$re1", Pattern: "bad[0-9]+", Type: "regex"},
		},
		References: []string{"https://example.com"},
	}
	out, err := ExportYARARule(rule)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(out, "rule TestExport : malware trojan") {
		t.Errorf("missing rule header: %s", out)
	}
	if !strings.Contains(out, `description = "Test export description"`) {
		t.Errorf("missing description: %s", out)
	}
	if !strings.Contains(out, `author = "Tester"`) {
		t.Errorf("missing author: %s", out)
	}
	if !strings.Contains(out, `$s1 = "evil" nocase`) {
		t.Errorf("missing text string: %s", out)
	}
	if !strings.Contains(out, "$hex1 = { CA FE BA BE }") {
		t.Errorf("missing hex string: %s", out)
	}
	if !strings.Contains(out, "$re1 = /bad[0-9]+/") {
		t.Errorf("missing regex string: %s", out)
	}
	if !strings.Contains(out, "$s1 or $hex1") {
		t.Errorf("missing condition: %s", out)
	}
}

func TestExportYARAMultipleRules(t *testing.T) {
	rules := []config.IDSRule{
		{
			ID:    "r1",
			Title: "RuleOne",
			Labels: map[string]string{
				"yara.condition": "true",
			},
		},
		{
			ID:    "r2",
			Title: "RuleTwo",
			Labels: map[string]string{
				"yara.condition": "true",
			},
		},
	}
	out, err := ExportYARARules(rules)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	s := string(out)
	if strings.Count(s, "rule ") != 2 {
		t.Errorf("expected 2 rules in output, got: %s", s)
	}
}

func TestExportSuricataContentModifiers(t *testing.T) {
	rule := config.IDSRule{
		ID:    "test-mods",
		Title: "Modifier Test",
		ContentMatches: []config.ContentMatch{
			{
				Pattern:  "test",
				Negate:   true,
				Distance: 5,
				Within:   10,
			},
		},
		Labels: map[string]string{},
	}
	out, err := ExportSuricataRule(rule)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(out, `content:!"test"`) {
		t.Errorf("missing negated content: %s", out)
	}
	if !strings.Contains(out, "distance:5") {
		t.Errorf("missing distance: %s", out)
	}
	if !strings.Contains(out, "within:10") {
		t.Errorf("missing within: %s", out)
	}
}

func TestExportSuricataDefaultValues(t *testing.T) {
	rule := config.IDSRule{
		ID:     "minimal",
		Title:  "Minimal",
		Labels: map[string]string{},
	}
	out, err := ExportSuricataRule(rule)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.HasPrefix(out, "alert ip any any -> any any") {
		t.Errorf("unexpected defaults: %s", out)
	}
}

func TestSeverityToPriority(t *testing.T) {
	cases := map[string]int{
		"critical": 1,
		"high":     2,
		"medium":   3,
		"low":      4,
		"":         0,
		"unknown":  0,
	}
	for sev, want := range cases {
		if got := severityToPriority(sev); got != want {
			t.Errorf("severityToPriority(%q) = %d, want %d", sev, got, want)
		}
	}
}

func TestExportSuricataCVEReference(t *testing.T) {
	rule := config.IDSRule{
		ID:         "cve-test",
		Title:      "CVE Test",
		References: []string{"CVE-2024-1234"},
		Labels:     map[string]string{},
	}
	out, err := ExportSuricataRule(rule)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(out, "reference:cve,CVE-2024-1234") {
		t.Errorf("missing CVE reference: %s", out)
	}
}
