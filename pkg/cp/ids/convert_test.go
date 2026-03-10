// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

package ids

import (
	"testing"

	"github.com/tonylturner/containd/pkg/cp/config"
)

func TestDetectFormatByExtension(t *testing.T) {
	cases := []struct {
		filename string
		data     string
		want     string
	}{
		{"rules.yml", "title: test\ndetection:\n  sel:\n    x: 1\n  condition: sel", FormatSigma},
		{"rules.yaml", "title: test\nlogsource:\n  product: test", FormatSigma},
		{"malware.yar", "rule Test { condition: true }", FormatYARA},
		{"malware.yara", "rule Test { condition: true }", FormatYARA},
		{"ids.rules", `alert tcp any any -> any 80 (msg:"test"; sid:1;)`, FormatSuricata},
	}
	for _, tc := range cases {
		got := DetectFormat(tc.filename, []byte(tc.data))
		if got != tc.want {
			t.Errorf("DetectFormat(%q) = %q, want %q", tc.filename, got, tc.want)
		}
	}
}

func TestDetectFormatByContent(t *testing.T) {
	cases := []struct {
		name string
		data string
		want string
	}{
		{
			name: "yara content",
			data: "rule TestRule {\n    condition:\n        true\n}",
			want: FormatYARA,
		},
		{
			name: "sigma content",
			data: "title: Test\ndetection:\n  sel:\n    x: 1",
			want: FormatSigma,
		},
		{
			name: "suricata content",
			data: `alert tcp any any -> any 80 (msg:"test"; sid:1;)`,
			want: FormatSuricata,
		},
	}
	for _, tc := range cases {
		got := DetectFormat("unknown.txt", []byte(tc.data))
		if got != tc.want {
			t.Errorf("DetectFormat(content: %s) = %q, want %q", tc.name, got, tc.want)
		}
	}
}

func TestDetectFormatUnknown(t *testing.T) {
	got := DetectFormat("unknown.txt", []byte("random data with no patterns"))
	if got != "" {
		t.Errorf("expected empty format for unknown content, got %q", got)
	}
}

func TestDetectFormatSuricataKeywords(t *testing.T) {
	// Suricata-specific keywords.
	data := `alert http any any -> any any (msg:"test"; app-layer-protocol:http; sid:1;)`
	got := DetectFormat("test.rules", []byte(data))
	if got != FormatSuricata {
		t.Errorf("expected suricata for app-layer-protocol, got %q", got)
	}
}

func TestImportSigma(t *testing.T) {
	data := []byte(`title: Test Rule
id: test-1
level: high
tags: [containd.proto.modbus]
detection:
  selection:
    function_code: 5
  condition: selection
`)
	rules, err := Import(FormatSigma, data)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(rules) != 1 {
		t.Fatalf("expected 1 rule, got %d", len(rules))
	}
	if rules[0].ID != "test-1" {
		t.Errorf("unexpected ID: %s", rules[0].ID)
	}
}

func TestImportSigmaMultiDoc(t *testing.T) {
	data := []byte(`title: Rule One
id: r1
detection:
  sel:
    x: 1
  condition: sel
---
title: Rule Two
id: r2
detection:
  sel:
    y: 2
  condition: sel
`)
	rules, err := Import(FormatSigma, data)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(rules) != 2 {
		t.Fatalf("expected 2 rules, got %d", len(rules))
	}
}

func TestImportYARA(t *testing.T) {
	data := []byte(`rule TestRule {
    strings:
        $a = "test"
    condition:
        $a
}`)
	rules, err := Import(FormatYARA, data)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(rules) != 1 {
		t.Fatalf("expected 1 rule, got %d", len(rules))
	}
	if rules[0].SourceFormat != "yara" {
		t.Errorf("unexpected source format: %s", rules[0].SourceFormat)
	}
}

func TestImportUnsupported(t *testing.T) {
	_, err := Import("unknown", []byte("data"))
	if err == nil {
		t.Fatal("expected error for unsupported format")
	}
}

func TestExportDispatcher(t *testing.T) {
	rules := []config.IDSRule{
		{ID: "test-1", Title: "Test", Labels: map[string]string{}},
	}
	formats := []string{FormatSigma, FormatSuricata, FormatSnort, FormatYARA}
	for _, fmt := range formats {
		out, err := Export(fmt, rules)
		if err != nil {
			t.Errorf("Export(%s) error: %v", fmt, err)
		}
		if len(out) == 0 {
			t.Errorf("Export(%s) returned empty output", fmt)
		}
	}
}

func TestExportUnsupported(t *testing.T) {
	_, err := Export("unknown", nil)
	if err == nil {
		t.Fatal("expected error for unsupported export format")
	}
}

func TestImportSuricataNotImplemented(t *testing.T) {
	_, err := Import(FormatSuricata, []byte("data"))
	if err == nil {
		t.Fatal("expected error for unimplemented suricata import")
	}
}

func TestImportSnortNotImplemented(t *testing.T) {
	_, err := Import(FormatSnort, []byte("data"))
	if err == nil {
		t.Fatal("expected error for unimplemented snort import")
	}
}
