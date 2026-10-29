// SPDX-License-Identifier: Apache-2.0
package ids

import (
	"encoding/json"
	"errors"
	"io"
	"strconv"
	"strings"
	"testing"

	"github.com/tonylturner/containd/pkg/cp/config"
	"gopkg.in/yaml.v3"
)

const sigmaExportSource = "title: Test\nlogsource: {product: test}\ndetection:\n  selection:\n    function_code: 5\n  condition: selection\n"
const yaraExportSource = `rule Content { strings: $a = "test" condition: $a }`

func TestYARAExportLiteralNewline(t *testing.T) {
	text, err := ExportYARARule(config.IDSRule{
		ID: "literal", YARAStrings: []config.YARAString{{Name: "$a", Pattern: "a\nb"}},
	})
	if err != nil || !strings.Contains(text, `$a = "a\nb"`) {
		t.Fatalf("literal content = %q, %v", text, err)
	}
}

func TestYARAExportPredicates(t *testing.T) {
	leaf := config.IDSCondition{Field: "attr.function_code", Op: "equals", Value: 5}
	pure := config.IDSRule{ID: "pure", YARAStrings: []config.YARAString{{Name: "$a", Pattern: "test", Type: "text"}}}
	const format = FormatYARA
	single := ExportYARARule
	for _, tc := range []struct {
		name, predicate string
		rule            config.IDSRule
	}{
		{"protocol", "proto", config.IDSRule{Proto: "modbus"}},
		{"kind", "kind", config.IDSRule{Kind: "request"}},
		{"leaf", "attr.function_code", config.IDSRule{When: leaf}},
		{"all", "when.all", config.IDSRule{When: config.IDSCondition{All: []config.IDSCondition{leaf}}}},
		{"any", "when.any", config.IDSRule{When: config.IDSCondition{Any: []config.IDSCondition{leaf}}}},
		{"not", "when.not", config.IDSRule{When: config.IDSCondition{Not: &leaf}}},
		{"empty-not", "when.not", config.IDSRule{When: config.IDSCondition{Not: &config.IDSCondition{}}}},
		{"op-only", "when", config.IDSRule{When: config.IDSCondition{Op: "equals"}}},
		{"disabled", "enabled", config.IDSRule{Enabled: new(false)}},
		{"metadata-only", "", config.IDSRule{Title: "Not a detection"}},
		{"content-buffer", "", config.IDSRule{ContentMatches: []config.ContentMatch{{Pattern: "test"}}}},
	} {
		t.Run(format+"/"+tc.name, func(t *testing.T) {
			tc.rule.ID = "refused"
			text, err := single(tc.rule)
			var refusal *RuleExportError
			if text != "" || !errors.As(err, &refusal) || refusal.RuleID != tc.rule.ID ||
				refusal.Format != format || !strings.Contains(refusal.Predicate, tc.predicate) {
				t.Fatalf("export = %q, %v", text, err)
			}
		})
	}
	t.Run(format+"/pure-content", func(t *testing.T) {
		text, err := single(pure)
		if err != nil || !strings.Contains(text, `$a = "test"`) || !strings.Contains(text, "any of them") {
			t.Fatalf("pure content = %q, %v", text, err)
		}
	})
	raw := yaraExportSource
	for _, filter := range []string{"", "proto", "kind", "enabled"} {
		t.Run(format+"/raw/"+filter, func(t *testing.T) {
			rule := config.IDSRule{ID: "raw", SourceFormat: format, RawSource: raw}
			switch filter {
			case "proto":
				rule.Proto = "modbus"
			case "kind":
				rule.Kind = "request"
			case "enabled":
				rule.Enabled = new(false)
			}
			text, err := single(rule)
			if filter == "" {
				if err != nil || text != raw {
					t.Fatalf("round trip = %q, %v", text, err)
				}
			} else {
				var refusal *RuleExportError
				if text != "" || !errors.As(err, &refusal) || !strings.Contains(refusal.Predicate, filter) {
					t.Fatalf("raw source lost filter: %q, %v", text, err)
				}
			}
		})
	}
	for name, rule := range map[string]config.IDSRule{
		"raw-when": {SourceFormat: FormatYARA, RawSource: yaraExportSource, When: leaf},
		"source":   {SourceFormat: FormatSnort, YARAStrings: pure.YARAStrings},
		"missing":  {SourceFormat: FormatYARA, YARAStrings: pure.YARAStrings},
		"address":  {SrcAddr: "10.0.0.0/8", YARAStrings: pure.YARAStrings},
		"notes":    {ConversionNotes: []string{"unmapped"}, YARAStrings: pure.YARAStrings},
		"type":     {YARAStrings: []config.YARAString{{Name: "$a", Pattern: "test", Type: "unknown"}}},
		"name":     {ID: "123", YARAStrings: pure.YARAStrings},
		"tags":     {Labels: map[string]string{"yara.tags": "tag\nrule"}, YARAStrings: pure.YARAStrings},
		"condition": {Labels: map[string]string{"yara.condition": "true }\nrule injected { condition: true"},
			YARAStrings: pure.YARAStrings},
		"hex":   {YARAStrings: []config.YARAString{{Name: "$a", Pattern: "DE }", Type: "hex"}}},
		"regex": {YARAStrings: []config.YARAString{{Name: "$a", Pattern: "test/other", Type: "regex"}}},
	} {
		t.Run("yara/"+name, func(t *testing.T) {
			if text, err := ExportYARARule(rule); text != "" || err == nil {
				t.Fatalf("YARA widened: %q, %v", text, err)
			}
		})
	}
}

func TestContentExportRefusalReports(t *testing.T) {
	for _, format := range []string{FormatSigma, FormatYARA} {
		for _, accepted := range []int{0, 2} {
			t.Run(format+"/"+strconv.Itoa(accepted), func(t *testing.T) {
				prefix, raw := "#", sigmaExportSource
				if format == FormatYARA {
					prefix, raw = "//", yaraExportSource
				}
				rules := []config.IDSRule{{ID: "refused\nrule injected {}", SrcAddr: "10.0.0.0/8"}}
				for i := range accepted {
					source := raw
					if format == FormatYARA {
						source = strings.Replace(raw, "rule Content ", "rule Content"+strconv.Itoa(i)+" ", 1)
					}
					rule := config.IDSRule{ID: "accepted-" + strconv.Itoa(i), SourceFormat: format, RawSource: source}
					if format == FormatSigma {
						var err error
						rule, err = ConvertSigmaYAML([]byte(source))
						if err != nil {
							t.Fatal(err)
						}
					}
					rules = append(rules, rule)
				}
				out, err := ExportRules(rules, format)
				if err != nil || len(out.Refusals) != 1 {
					t.Fatalf("result = %+v, %v", out, err)
				}
				var body []string
				comments := 0
				for _, line := range strings.Split(string(out.Text), "\n") {
					if strings.HasPrefix(line, prefix+" refused: ") {
						var refusal ExportRefusal
						if err := json.Unmarshal([]byte(strings.TrimPrefix(line, prefix+" refused: ")), &refusal); err != nil {
							t.Fatal(err)
						}
						if refusal != out.Refusals[0] {
							t.Fatalf("comment = %+v, report = %+v", refusal, out.Refusals)
						}
						comments++
					} else if !strings.HasPrefix(line, prefix) {
						body = append(body, line)
					}
				}
				active := strings.TrimSpace(strings.Join(body, "\n"))
				if comments != 1 || strings.Contains(active, "injected") || (accepted == 0 && active != "") {
					t.Fatalf("invalid refusal file: %s", out.Text)
				}
				if format == FormatSigma && accepted > 0 {
					decoder := yaml.NewDecoder(strings.NewReader(active))
					docs := 0
					for {
						var doc map[string]any
						err := decoder.Decode(&doc)
						if errors.Is(err, io.EOF) {
							break
						}
						if err != nil || doc["detection"] == nil {
							t.Fatalf("invalid accepted document: %+v, %v", doc, err)
						}
						docs++
					}
					if docs != accepted {
						t.Fatalf("documents=%d want=%d", docs, accepted)
					}
				} else if strings.Count(active, "rule Content") != accepted {
					t.Fatalf("accepted rules lost or duplicated: %s", active)
				}
			})
		}
		t.Run(format+"/empty", func(t *testing.T) {
			out, err := ExportRules(nil, format)
			if err != nil || len(out.Text) != 0 || len(out.Refusals) != 0 {
				t.Fatalf("empty export = %+v, %v", out, err)
			}
		})
	}
}
