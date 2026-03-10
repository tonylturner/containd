// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

package ids

import (
	"testing"
)

func TestParseYARABasicRule(t *testing.T) {
	input := `rule TestMalware : trojan network {
    meta:
        author = "Analyst"
        description = "Detects test malware"
        severity = "high"
        reference = "https://example.com/advisory"
    strings:
        $s1 = "malicious_string" nocase
        $hex1 = { DE AD BE EF }
        $re1 = /evil[0-9]+/
    condition:
        any of them
}`
	r, err := ParseYARARule(input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if r.ID != "yara-testmalware" {
		t.Errorf("unexpected ID: %s", r.ID)
	}
	if r.Title != "TestMalware" {
		t.Errorf("unexpected Title: %s", r.Title)
	}
	if r.Description != "Detects test malware" {
		t.Errorf("unexpected Description: %s", r.Description)
	}
	if r.Severity != "high" {
		t.Errorf("unexpected Severity: %s", r.Severity)
	}
	if r.SourceFormat != "yara" {
		t.Errorf("unexpected SourceFormat: %s", r.SourceFormat)
	}
	if r.Labels["author"] != "Analyst" {
		t.Errorf("unexpected author label: %s", r.Labels["author"])
	}
	if r.Labels["yara.tags"] != "trojan,network" {
		t.Errorf("unexpected yara.tags: %s", r.Labels["yara.tags"])
	}
	if r.Labels["evaluable"] != "false" {
		t.Errorf("expected evaluable=false, got %s", r.Labels["evaluable"])
	}
	if r.Labels["yara.condition"] != "any of them" {
		t.Errorf("unexpected condition: %s", r.Labels["yara.condition"])
	}
	if len(r.References) != 1 || r.References[0] != "https://example.com/advisory" {
		t.Errorf("unexpected References: %v", r.References)
	}
	if len(r.ConversionNotes) != 1 {
		t.Errorf("expected 1 conversion note, got %d", len(r.ConversionNotes))
	}

	// Verify strings parsing.
	if len(r.YARAStrings) != 3 {
		t.Fatalf("expected 3 YARA strings, got %d", len(r.YARAStrings))
	}

	s1 := r.YARAStrings[0]
	if s1.Name != "$s1" || s1.Type != "text" || s1.Pattern != "malicious_string" || !s1.Nocase {
		t.Errorf("unexpected string[0]: %+v", s1)
	}

	hex := r.YARAStrings[1]
	if hex.Name != "$hex1" || hex.Type != "hex" || hex.Pattern != "DE AD BE EF" {
		t.Errorf("unexpected string[1]: %+v", hex)
	}

	re := r.YARAStrings[2]
	if re.Name != "$re1" || re.Type != "regex" || re.Pattern != "evil[0-9]+" {
		t.Errorf("unexpected string[2]: %+v", re)
	}
}

func TestParseYARANoMeta(t *testing.T) {
	input := `rule SimpleRule {
    strings:
        $a = "test"
    condition:
        $a
}`
	r, err := ParseYARARule(input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if r.Title != "SimpleRule" {
		t.Errorf("unexpected Title: %s", r.Title)
	}
	if len(r.YARAStrings) != 1 {
		t.Fatalf("expected 1 string, got %d", len(r.YARAStrings))
	}
	if r.Labels["yara.condition"] != "$a" {
		t.Errorf("unexpected condition: %s", r.Labels["yara.condition"])
	}
}

func TestParseYARAWideASCII(t *testing.T) {
	input := `rule WideTest {
    strings:
        $w = "wide_string" wide ascii nocase
    condition:
        $w
}`
	r, err := ParseYARARule(input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(r.YARAStrings) != 1 {
		t.Fatalf("expected 1 string, got %d", len(r.YARAStrings))
	}
	s := r.YARAStrings[0]
	if !s.Wide || !s.ASCII || !s.Nocase {
		t.Errorf("expected wide+ascii+nocase, got %+v", s)
	}
}

func TestConvertYARAFileMultiRule(t *testing.T) {
	input := []byte(`
// YARA rule file
import "pe"

rule FirstRule {
    meta:
        description = "First"
    strings:
        $a = "first"
    condition:
        $a
}

/* Multi-line comment */
rule SecondRule : tag1 {
    meta:
        description = "Second"
    strings:
        $b = "second"
    condition:
        $b
}
`)
	rules, err := ConvertYARAFile(input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(rules) != 2 {
		t.Fatalf("expected 2 rules, got %d", len(rules))
	}
	if rules[0].Title != "FirstRule" {
		t.Errorf("unexpected first rule title: %s", rules[0].Title)
	}
	if rules[1].Title != "SecondRule" {
		t.Errorf("unexpected second rule title: %s", rules[1].Title)
	}
	if rules[1].Labels["yara.tags"] != "tag1" {
		t.Errorf("unexpected tags on second rule: %s", rules[1].Labels["yara.tags"])
	}
}

func TestParseYARAEmptyInput(t *testing.T) {
	_, err := ParseYARARule("")
	if err == nil {
		t.Fatal("expected error for empty input")
	}
}

func TestParseYARAInvalidHeader(t *testing.T) {
	_, err := ParseYARARule("not a yara rule")
	if err == nil {
		t.Fatal("expected error for invalid header")
	}
}

func TestConvertYARAFileNoRules(t *testing.T) {
	_, err := ConvertYARAFile([]byte("// just a comment"))
	if err == nil {
		t.Fatal("expected error for file with no rules")
	}
}

func TestStripYARAComments(t *testing.T) {
	input := `// single line comment
rule Test {
    /* block comment */
    meta:
        author = "test" // inline comment
    condition:
        true
}`
	result := stripYARAComments(input)
	if containsAny(result, "single line comment", "block comment", "inline comment") {
		t.Errorf("comments not fully stripped: %s", result)
	}
	if !containsAll(result, "rule Test", "author", "condition") {
		t.Errorf("rule content was stripped: %s", result)
	}
}

func containsAny(s string, substrs ...string) bool {
	for _, sub := range substrs {
		if contains(s, sub) {
			return true
		}
	}
	return false
}

func containsAll(s string, substrs ...string) bool {
	for _, sub := range substrs {
		if !contains(s, sub) {
			return false
		}
	}
	return true
}

func contains(s, sub string) bool {
	return len(s) >= len(sub) && searchString(s, sub)
}

func searchString(s, sub string) bool {
	for i := 0; i <= len(s)-len(sub); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}

func TestParseYARAPrivateRule(t *testing.T) {
	input := `private rule PrivateTest {
    strings:
        $a = "private"
    condition:
        $a
}`
	r, err := ParseYARARule(input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if r.Title != "PrivateTest" {
		t.Errorf("unexpected Title: %s", r.Title)
	}
}
