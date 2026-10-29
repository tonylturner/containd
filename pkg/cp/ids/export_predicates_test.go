// SPDX-License-Identifier: Apache-2.0
package ids

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/tonylturner/containd/pkg/cp/config"
)

func TestSnortExportProtocolAllowlist(t *testing.T) {
	testRulesFileProtocolAllowlist(t, FormatSnort, ExportSnortRule)
}

func TestSuricataExportProtocolAllowlist(t *testing.T) {
	testRulesFileProtocolAllowlist(t, FormatSuricata, ExportSuricataRule)
}

func testRulesFileProtocolAllowlist(t *testing.T, format string, export func(config.IDSRule) (string, error)) {
	t.Helper()
	for _, proto := range []string{"", "ip", "tcp", "UDP", "icmp", "modbus", "dnp3", "cip", "enip",
		"iec104", "http", "dns", "tls", "ssh", "ftp", "smtp", "s7comm", "bacnet", "opcua", "mms",
		"iec61850", "goose", "future-protocol"} {
		t.Run(proto, func(t *testing.T) {
			rule := config.IDSRule{ID: "protocol-test", Proto: proto}
			text, err := export(rule)
			switch strings.ToLower(proto) {
			case "", "ip", "tcp", "udp", "icmp":
				if err != nil || !strings.HasPrefix(text, "alert "+strings.ToLower(firstNonEmpty(proto, "ip"))+" ") {
					t.Fatalf("transport export = %q, %v", text, err)
				}
			default:
				var refusal *RuleExportError
				if text != "" || !errors.As(err, &refusal) || !errors.Is(err, ErrUnexportableProto) ||
					refusal.RuleID != rule.ID || !strings.Contains(refusal.Predicate, proto) {
					t.Fatalf("application export = %q, %v", text, err)
				}
			}
			// RawSource is the authority for same-format imported rules, even
			// when normalized protocol enrichment cannot be reversed.
			raw := "alert tcp any any -> any 502 (modbus_func:5; sid:9;)\n"
			rule.SourceFormat, rule.RawSource = format, raw
			text, err = export(rule)
			if err != nil || text != raw {
				t.Fatalf("round-trip = %q, %v", text, err)
			}
		})
	}
}

func TestSnortExportRefusesConditions(t *testing.T) {
	testRulesFileConditions(t, ExportSnortRule)
}

func TestSuricataExportRefusesConditions(t *testing.T) {
	testRulesFileConditions(t, ExportSuricataRule)
}

func testRulesFileConditions(t *testing.T, export func(config.IDSRule) (string, error)) {
	t.Helper()
	for _, proto := range []string{"tcp", "modbus", "dnp3", "cip", "iec104"} {
		for _, field := range []string{"service", "attr.function_code", "attr.unit_id", "attr.data",
			"attr.object_group", "attr.indications", "attr.service_code", "attr.attribute",
			"attr.object_class", "attr.instance", "attr.enip_command", "unknown"} {
			for _, op := range []string{"equals", "in", "contains", "regex", "gt", "lt"} {
				leaf := config.IDSCondition{Field: field, Op: op, Value: 5}
				for name, condition := range map[string]config.IDSCondition{
					"leaf": leaf,
					"all":  {All: []config.IDSCondition{leaf}},
					"any":  {Any: []config.IDSCondition{leaf}},
					"not":  {Not: &leaf},
				} {
					t.Run(proto+"/"+field+"/"+op+"/"+name, func(t *testing.T) {
						rule := config.IDSRule{ID: "predicate-test", Proto: proto, When: condition}
						text, err := export(rule)
						var refusal *RuleExportError
						if text != "" || !errors.As(err, &refusal) || refusal.RuleID != rule.ID {
							t.Fatalf("predicate widened: %q, %v", text, err)
						}
						if proto == "tcp" && !strings.Contains(refusal.Predicate, field) {
							t.Fatalf("missing unsupported field: %v", err)
						}
					})
				}
			}
		}
	}
	for name, rule := range map[string]config.IDSRule{
		"kind":         {Kind: "request"},
		"cross-format": {SourceFormat: "sigma", RawSource: "detection: {}"},
		"notes":        {ConversionNotes: []string{"flow not mapped"}},
		"yara":         {YARAStrings: []config.YARAString{{Name: "$a", Pattern: "x"}}},
		"empty-not":    {When: config.IDSCondition{Not: &config.IDSCondition{}}},
		"op-only":      {When: config.IDSCondition{Op: "equals"}},
		"negative":     {ContentMatches: []config.ContentMatch{{Pattern: "x", Offset: -1}}},
		"pipe":         {ContentMatches: []config.ContentMatch{{Pattern: "a|20|b"}}},
		"bad-hex":      {ContentMatches: []config.ContentMatch{{Pattern: "DE ??", IsHex: true}}},
		"multiline":    {ContentMatches: []config.ContentMatch{{Pattern: "a\nb"}}},
		"disabled":     {Enabled: new(false)},
	} {
		t.Run(name, func(t *testing.T) {
			text, err := export(rule)
			var refusal *RuleExportError
			if text != "" || !errors.As(err, &refusal) {
				t.Fatalf("unsupported rule widened: %q, %v", text, err)
			}
		})
	}
}

func TestSnortExportRefusalReport(t *testing.T) {
	testRulesFileRefusalReport(t, ExportSnortRules)
}

func TestSuricataExportRefusalReport(t *testing.T) {
	testRulesFileRefusalReport(t, ExportSuricataRules)
}

func testRulesFileRefusalReport(t *testing.T, export func([]config.IDSRule) (ExportResult, error)) {
	t.Helper()
	for _, accepted := range []bool{false, true} {
		rules := []config.IDSRule{
			{ID: "refused\nalert ip any any -> any any (sid:99;)", Proto: "modbus"},
			{ID: "unsupported-condition", When: config.IDSCondition{Field: "attr.function_code", Value: 5}},
		}
		if accepted {
			rules = append(rules, config.IDSRule{ID: "1", Proto: "tcp"})
		}
		out, err := export(rules)
		if err != nil || len(out.Refusals) != 2 {
			t.Fatalf("report = %+v, %v", out, err)
		}
		comments, active := 0, 0
		for _, line := range strings.Split(strings.TrimSpace(string(out.Text)), "\n") {
			if strings.HasPrefix(line, "# refused: ") {
				var refusal ExportRefusal
				if err := json.Unmarshal([]byte(strings.TrimPrefix(line, "# refused: ")), &refusal); err != nil {
					t.Fatal(err)
				}
				if refusal != out.Refusals[comments] {
					t.Fatalf("comment %+v != report %+v", refusal, out.Refusals[comments])
				}
				comments++
			} else if !strings.HasPrefix(line, "#") {
				active++
				if !strings.HasPrefix(line, "alert tcp ") {
					t.Fatalf("unexpected active rule: %s", line)
				}
			}
		}
		if comments != 2 || active != map[bool]int{true: 1, false: 0}[accepted] {
			t.Fatalf("comments=%d active=%d", comments, active)
		}
	}
	out, err := export(nil)
	if err != nil || len(out.Text) != 0 || len(out.Refusals) != 0 {
		t.Fatalf("empty export = %+v, %v", out, err)
	}
}

func TestSnort3ContentSyntax(t *testing.T) {
	out, err := ExportSnortRule(config.IDSRule{ID: "1", Proto: "tcp", ContentMatches: []config.ContentMatch{
		{Pattern: "DE AD", IsHex: true, Nocase: true, Depth: 20, Offset: 1},
		{Pattern: "x", Negate: true, Distance: -2, Within: 10},
	}})
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{`content:"|DE AD|", nocase, depth 20, offset 1;`, `content:!"x", distance -2, within 10;`} {
		if !strings.Contains(out, want) {
			t.Fatalf("missing %q in %s", want, out)
		}
	}
}

func TestSuricataContentSyntax(t *testing.T) {
	out, err := ExportSuricataRule(config.IDSRule{ID: "1", Proto: "tcp", ContentMatches: []config.ContentMatch{
		{Pattern: "DE AD", IsHex: true, Nocase: true},
		{Pattern: "x", Negate: true, Distance: -2, Within: 10},
	}})
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{`content:"|DE AD|"; nocase;`, `content:!"x"; distance:-2; within:10;`} {
		if !strings.Contains(out, want) {
			t.Fatalf("missing %q in %s", want, out)
		}
	}
}
