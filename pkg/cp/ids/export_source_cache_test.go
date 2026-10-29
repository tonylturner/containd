// SPDX-License-Identifier: Apache-2.0
package ids

import (
	"errors"
	"strings"
	"testing"

	"github.com/tonylturner/containd/pkg/cp/config"
)

func cacheTestRule(t *testing.T, format, source string) config.IDSRule {
	t.Helper()
	rules, err := ImportRules([]byte(source), format)
	if err != nil || len(rules) != 1 {
		t.Fatalf("import=%+v,%v", rules, err)
	}
	// Cache bytes may include comments/spacing beyond the converter's normalized
	// RawSource. A valid cache must be returned exactly, not re-marshalled.
	rules[0].RawSource = source
	return rules[0]
}

func cacheTestExport(t *testing.T, rule config.IDSRule, format string) (string, error) {
	t.Helper()
	switch format {
	case FormatSnort:
		return ExportSnortRule(rule)
	case FormatSuricata:
		return ExportSuricataRule(rule)
	case FormatYARA:
		return ExportYARARule(rule)
	default:
		data, err := ExportSigmaRule(rule)
		return string(data), err
	}
}

func TestExportSourceCache(t *testing.T) {
	sources := map[string]string{
		FormatSnort:    "# cached Snort\nalert tcp any any -> any any (msg:\"Cache\"; sid:7; rev:9;)\n",
		FormatSuricata: "# cached Suricata\nalert tcp any any -> any any (msg:\"Cache\"; sid:7; rev:9;)\n",
		FormatSigma:    "# cached Sigma\nid: cache\ntitle: Cache\ndetection: {selection: {unit_id: 1}, condition: selection}\n",
		FormatYARA:     "// cached YARA\nrule Cache {\n strings:\n  $a = \"first\"\n condition:\n  $a\n}\n",
	}
	for format, source := range sources {
		t.Run(format, func(t *testing.T) {
			t.Run("unchanged", func(t *testing.T) {
				rule := cacheTestRule(t, format, source)
				text, err := cacheTestExport(t, rule, format)
				if err != nil || text != source {
					t.Fatalf("unchanged=%q,%v", text, err)
				}
			})
			t.Run("equivalent-storage", func(t *testing.T) {
				rule := cacheTestRule(t, format, source)
				rule.Enabled = new(true)
				if format == FormatSigma {
					rule.When.Value = float64(1)
					rule.When.Op = ""
					rule.When = config.IDSCondition{All: []config.IDSCondition{rule.When}}
				}
				text, err := cacheTestExport(t, rule, format)
				if err != nil || text != source {
					t.Fatalf("equivalent=%q,%v", text, err)
				}
			})
			for _, state := range []string{"edited", "corrupt", "multiple"} {
				t.Run(state, func(t *testing.T) {
					rule := cacheTestRule(t, format, source)
					predicate := "proto"
					switch state {
					case "edited":
						switch format {
						case FormatSigma:
							rule.When.Value = 2
							predicate = "when"
						case FormatYARA:
							rule.YARAStrings[0].Pattern = "second"
							predicate = "yaraStrings"
						default:
							rule.Proto = "udp"
						}
					case "corrupt":
						rule.RawSource = "this is not a valid rule ["
					case "multiple":
						sep := "\n"
						if format == FormatSigma {
							sep = "\n---\n"
						}
						rule.RawSource = source + sep + source
					}
					text, err := cacheTestExport(t, rule, format)
					if text == rule.RawSource || text == source {
						t.Fatalf("stale cache reused: %q,%v", text, err)
					}
					if format == FormatYARA {
						// YARA imports always carry a non-evaluable conversion note. Without
						// valid source, that warning must not be erased to regenerate a rule.
						if state != "edited" {
							predicate = "conversionNotes"
						}
						var refusal *RuleExportError
						if text != "" || !errors.As(err, &refusal) || !strings.Contains(refusal.Predicate, predicate) {
							t.Fatalf("lossy fallback=%q,%v", text, err)
						}
						return
					}
					if err != nil {
						t.Fatal(err)
					}
					got := cacheTestRule(t, format, text)
					if format == FormatSigma {
						assertSigmaRoundTrip(t, rule, []byte(text))
					} else if got.Proto != rule.Proto {
						t.Fatalf("wrong edited proto: %+v", got)
					}
				})
			}
			t.Run("unsupported-edit", func(t *testing.T) {
				rule := cacheTestRule(t, format, source)
				rule.Kind = "new-kind"
				predicate := "kind"
				if format == FormatSigma {
					rule.When.Field = "attr.unsupported"
					predicate = "when.field"
				}
				text, err := cacheTestExport(t, rule, format)
				var refusal *RuleExportError
				if text != "" || !errors.As(err, &refusal) || !strings.Contains(refusal.Predicate, predicate) {
					t.Fatalf("unrepresentable edit=%q,%v", text, err)
				}
			})
		})
	}
}

func TestExportSourceCacheBytePredicates(t *testing.T) {
	for _, format := range []string{FormatSnort, FormatSuricata, FormatYARA} {
		source := "alert tcp any any -> any any (content:\"first\"; nocase; sid:7;)"
		if format == FormatYARA {
			source = "rule Cache {\n strings:\n  $a = \"first\" nocase\n condition:\n  $a\n}"
		}
		for _, edited := range []string{"pattern", "modifier", "condition", "action"} {
			t.Run(format+"/"+edited, func(t *testing.T) {
				rule := cacheTestRule(t, format, source)
				predicate := "contentMatches"
				if format == FormatYARA {
					predicate = "yaraStrings"
					switch edited {
					case "pattern":
						rule.YARAStrings[0].Pattern = "second"
					case "modifier":
						rule.YARAStrings[0].Nocase = false
					case "condition":
						rule.Labels["yara.condition"] = "$a and false"
						predicate = "yara.condition"
					case "action":
						rule.Action = "drop"
						predicate = "action"
					}
				} else {
					switch edited {
					case "pattern":
						rule.ContentMatches[0].Pattern = "second"
					case "modifier":
						rule.ContentMatches[0].Nocase = false
					case "condition":
						rule.When = config.IDSCondition{Field: "attr.path", Op: "contains", Value: "second"}
						predicate = "when"
					case "action":
						rule.Action = "drop"
						predicate = "action"
					}
				}
				text, err := cacheTestExport(t, rule, format)
				var refusal *RuleExportError
				if text != "" || !errors.As(err, &refusal) || !strings.Contains(refusal.Predicate, predicate) {
					t.Fatalf("stale byte predicate=%q,%v", text, err)
				}
			})
		}
	}
}

func TestExportSourceCacheNativeYARAFallback(t *testing.T) {
	rule := config.IDSRule{ID: "native-yara", SourceFormat: FormatYARA, RawSource: "corrupt source", YARAStrings: []config.YARAString{{Name: "$a", Pattern: "second"}}}
	text, err := ExportYARARule(rule)
	if err != nil || !strings.Contains(text, `$a = "second"`) {
		t.Fatalf("exact native fallback=%q,%v", text, err)
	}
}
