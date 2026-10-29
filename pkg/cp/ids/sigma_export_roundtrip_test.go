// SPDX-License-Identifier: Apache-2.0
package ids

import (
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"math/rand"
	"os"
	"reflect"
	"sort"
	"strings"
	"testing"
	"unicode/utf16"

	"github.com/tonylturner/containd/pkg/cp/config"
	"gopkg.in/yaml.v3"
)

func sigmaLeaf(field, op string, value any) config.IDSCondition {
	return config.IDSCondition{Field: field, Op: op, Value: value}
}

func TestSigmaExportRoundTripPredicates(t *testing.T) {
	leaves := []config.IDSCondition{
		sigmaLeaf("attr.function_code", "in", []any{5, 6, 15, 16}),
		sigmaLeaf("attr.unit_id", "equals", 5),
		sigmaLeaf("attr.path", "contains", "/admin"),
		sigmaLeaf("attr.sni", "regex", "^example\\.org$"),
		sigmaLeaf("attr.value", "gt", 1.25),
		sigmaLeaf("attr.quantity", "lt", int64(50)),
		sigmaLeaf("proto", "equals", "http"),
		sigmaLeaf("kind", "equals", "request"),
		sigmaLeaf("flowid", "equals", "a-b-c"),
		sigmaLeaf("attr.src_port", "equals", uint16(502)),
		sigmaLeaf("attr.dst_port", "in", []string{"502", "20000"}),
		sigmaLeaf("attr.msp", "equals", true),
		sigmaLeaf("attr.status", "in", []any{}),
		sigmaLeaf("attr.path", "in", "/one"),
		sigmaLeaf("attr.value", "equals", nil),
		sigmaLeaf("attr.value", "equals", float32(1.2)),
		sigmaLeaf("attr.value", "equals", float64(1)),
		sigmaLeaf("attr.unit_id", "", 2),
		sigmaLeaf("attr.value", "equals", map[string]any{"nested": []any{1, "one", true}}),
		sigmaLeaf("attr.value", "in", []any{[]any{1, "one"}, map[string]any{"a": 2}, 3}),
	}
	var corpus []config.IDSRule
	for i, leaf := range leaves {
		corpus = append(corpus, config.IDSRule{ID: fmt.Sprintf("leaf-%d", i), When: leaf})
	}
	// Repeated fields and nested same-operator groups used to collide in export.
	rng := rand.New(rand.NewSource(17))
	var tree func(int) config.IDSCondition
	tree = func(depth int) config.IDSCondition {
		if depth == 0 {
			return leaves[rng.Intn(len(leaves))]
		}
		switch rng.Intn(3) {
		case 0:
			child := tree(depth - 1)
			return config.IDSCondition{Not: &child}
		case 1:
			return config.IDSCondition{All: []config.IDSCondition{tree(depth - 1), tree(depth - 1)}}
		default:
			return config.IDSCondition{Any: []config.IDSCondition{tree(depth - 1), tree(depth - 1)}}
		}
	}
	for i := range 100 {
		corpus = append(corpus, config.IDSRule{ID: fmt.Sprintf("tree-%d", i), Proto: "modbus", Kind: "request", When: tree(3), Severity: []string{"", "low", "medium", "high", "critical"}[i%5], Enabled: new(true)})
	}
	corpus = append(corpus, config.IDSRule{ID: "singleton", When: config.IDSCondition{All: []config.IDSCondition{leaves[0]}}, Labels: map[string]string{
		"sigma.logsource": "product: containd\ncategory: network\n", "sigma.status": "stable", "sigma.references": "https://example.org/rule",
		"sigma.tags": "attack.discovery,containd.proto.dnp3,proto.cip,containd.kind.reply,kind.response",
	}})
	// Exercise both exact-source export and inverse generation after discarding it.
	fixture, err := os.ReadFile("../../../docs/examples/sigma-modbus-write.yml")
	if err != nil {
		t.Fatal(err)
	}
	for i, source := range []string{string(fixture), sigmaExportSource,
		"title: Boolean fixture\nlevel: moderate\ntags: [containd.proto.cip, containd.kind.request]\nlogsource: {product: containd}\ndetection:\n  a: {service_code: 16, object_class: 4}\n  b: {instance_id|gt: 1}\n  c: {attribute_id: [1, 2]}\n  condition: a and (b or not c)\n",
		"title: Wildcard fixture\ndetection:\n  selection1: {unit_id: 1}\n  selection2: {function_code: 2}\n  condition: selection*\n",
	} {
		rules, err := ConvertSigmaFile([]byte(source))
		if err != nil {
			t.Fatal(err)
		}
		for _, rule := range rules {
			rule.ID = fmt.Sprintf("fixture-%d", i)
			corpus = append(corpus, rule)
			rule.RawSource = ""
			rule.ID += "-native"
			corpus = append(corpus, rule)
		}
	}
	for _, rule := range corpus {
		t.Run(rule.ID, func(t *testing.T) {
			text, err := ExportSigmaRule(rule)
			if err != nil {
				t.Fatal(err)
			}
			if rule.RawSource != "" && string(text) != rule.RawSource {
				t.Fatal("raw source changed")
			}
			assertSigmaRoundTrip(t, rule, text)
			if rule.ID == "singleton" {
				got, err := ConvertSigmaYAML(text)
				if err != nil {
					t.Fatal(err)
				}
				for _, key := range []string{"sigma.status", "sigma.references"} {
					if got.Labels[key] != rule.Labels[key] {
						t.Fatalf("%s lost: %q", key, got.Labels[key])
					}
				}
				var wantLog, gotLog map[string]any
				if err := yaml.Unmarshal([]byte(rule.Labels["sigma.logsource"]), &wantLog); err != nil {
					t.Fatal(err)
				}
				if err := yaml.Unmarshal([]byte(got.Labels["sigma.logsource"]), &gotLog); err != nil {
					t.Fatal(err)
				}
				if !reflect.DeepEqual(wantLog, gotLog) {
					t.Fatalf("logsource lost: %v", gotLog)
				}
				if got.Labels["sigma.tags"] != "attack.discovery" {
					t.Fatalf("stale filter tags survived: %s", got.Labels["sigma.tags"])
				}
			}
		})
	}
	// The file API must keep the same number of active rules, without refusals.
	out, err := ExportSigmaRules(corpus)
	if err != nil || len(out.Refusals) != 0 {
		t.Fatalf("bulk = %+v, %v", out.Refusals, err)
	}
	imported, err := ConvertSigmaFile(out.Text)
	if err != nil || len(imported) != len(corpus) {
		t.Fatalf("bulk import = %d rules, %v", len(imported), err)
	}
}

// Independent predicate projection for the property assertion. JSON normalizes
// YAML/JSON numeric containers; only singleton/commutative Boolean storage and
// the documented default equals operator are normalized, not leaf predicates.
func sigmaTestCondition(t *testing.T, c config.IDSCondition) any {
	t.Helper()
	if c.Field != "" {
		if c.Op == "" {
			c.Op = "equals"
		}
		// The evaluator promotes float32 to float64, not its shorter printed decimal.
		if value, ok := c.Value.(float32); ok {
			c.Value = float64(value)
		}
		b, err := json.Marshal(c)
		if err != nil {
			t.Fatal(err)
		}
		var value any
		if err := json.Unmarshal(b, &value); err != nil {
			t.Fatal(err)
		}
		return value
	}
	if c.Not != nil {
		return map[string]any{"not": sigmaTestCondition(t, *c.Not)}
	}
	for _, group := range []struct {
		name     string
		children []config.IDSCondition
	}{{"all", c.All}, {"any", c.Any}} {
		if len(group.children) == 0 {
			continue
		}
		if len(group.children) == 1 {
			return sigmaTestCondition(t, group.children[0])
		}
		values := make([]any, len(group.children))
		for i, child := range group.children {
			values[i] = sigmaTestCondition(t, child)
		}
		sort.Slice(values, func(i, j int) bool {
			a, _ := json.Marshal(values[i])
			b, _ := json.Marshal(values[j])
			return string(a) < string(b)
		})
		return map[string]any{group.name: values}
	}
	return nil
}

func assertSigmaRoundTrip(t *testing.T, rule config.IDSRule, text []byte) {
	t.Helper()
	var sr SigmaRule
	if err := yaml.Unmarshal(text, &sr); err != nil {
		t.Fatal(err)
	}
	got, err := ConvertSigmaRule(sr)
	if err != nil {
		t.Fatal(err)
	}
	project := func(r config.IDSRule) any {
		return []any{sigmaTestCondition(t, r.When), r.Proto, r.Kind, r.SrcAddr, r.DstAddr, r.SrcPort, r.DstPort,
			r.Enabled == nil || *r.Enabled, r.Severity, r.Labels["evaluable"] != "false"}
	}
	if !reflect.DeepEqual(project(rule), project(got)) {
		t.Fatalf("predicates changed\nwant: %#v\n got: %#v\n%s", project(rule), project(got), text)
	}
}

func TestSigmaExportRefusedPredicates(t *testing.T) {
	leaf := sigmaLeaf("attr.function_code", "equals", 5)
	for _, tc := range []struct {
		name, predicate string
		change          func(*config.IDSRule)
	}{
		{"source address", "srcAddr", func(r *config.IDSRule) { r.SrcAddr = "10.0.0.0/8" }},
		{"destination address", "dstAddr", func(r *config.IDSRule) { r.DstAddr = "any" }},
		{"source port", "srcPort", func(r *config.IDSRule) { r.SrcPort = "502" }},
		{"destination port", "dstPort", func(r *config.IDSRule) { r.DstPort = "any" }},
		{"content", "contentMatches", func(r *config.IDSRule) { r.ContentMatches = []config.ContentMatch{{Pattern: "x"}} }},
		{"yara", "yaraStrings", func(r *config.IDSRule) { r.YARAStrings = []config.YARAString{{Pattern: "x"}} }},
		{"missing identity", "id", func(r *config.IDSRule) { r.ID = ""; r.Title = "Has a title" }},
		{"disabled", "enabled", func(r *config.IDSRule) { r.Enabled = new(false) }},
		{"unknown field", "when.field", func(r *config.IDSRule) { r.When.Field = "attr.unknown" }},
		{"unmapped alias", "when.field", func(r *config.IDSRule) { r.When.Field = "attr.http_uri" }},
		{"unknown op", "when.op", func(r *config.IDSRule) { r.When.Op = "startswith" }},
		{"list equals", "when.value", func(r *config.IDSRule) { r.When.Value = []any{5, 6} }},
		{"list contains", "when.value", func(r *config.IDSRule) { r.When.Op = "contains"; r.When.Value = []string{"a", "b"} }},
		{"typed numeric list", "when.value", func(r *config.IDSRule) { r.When.Op = "in"; r.When.Value = []int{1, 2} }},
		{"byte string", "when.value", func(r *config.IDSRule) { r.When.Value = []byte("foo") }},
		{"non-string map keys", "when.value", func(r *config.IDSRule) { r.When.Value = map[int]string{1: "a"} }},
		{"nested byte string", "when.value", func(r *config.IDSRule) { r.When.Op = "in"; r.When.Value = []any{[]byte("a")} }},
		{"nan", "when.value", func(r *config.IDSRule) { r.When.Value = math.NaN() }},
		{"empty when", "when", func(r *config.IDSRule) { r.When = config.IDSCondition{} }},
		{"mixed branches", "when", func(r *config.IDSRule) { r.When.All = []config.IDSCondition{leaf} }},
		{"nested unknown", "when.not.field", func(r *config.IDSRule) { bad := sigmaLeaf("bad", "equals", 5); r.When = config.IDSCondition{Not: &bad} }},
		{"severity", "severity", func(r *config.IDSRule) { r.Severity = "moderate" }},
		{"removed protocol", "proto", func(r *config.IDSRule) { r.Proto = "enip" }},
		{"unevaluable", "evaluable", func(r *config.IDSRule) { r.Labels = map[string]string{"evaluable": "false"} }},
		{"lost source constraints", "conversionNotes", func(r *config.IDSRule) { r.ConversionNotes = []string{"unmapped"} }},
		{"invalid logsource", "sigma.logsource", func(r *config.IDSRule) { r.Labels = map[string]string{"sigma.logsource": "[a,b]"} }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rule := config.IDSRule{ID: "refused", When: leaf}
			tc.change(&rule)
			text, err := ExportSigmaRule(rule)
			var refusal *RuleExportError
			if len(text) != 0 || !errors.As(err, &refusal) || refusal.RuleID != rule.ID || !strings.Contains(refusal.Predicate, tc.predicate) {
				t.Fatalf("export = %q, %v", text, err)
			}
			out, err := ExportSigmaRules([]config.IDSRule{rule})
			if err != nil || len(out.Refusals) != 1 || !strings.Contains(string(out.Text), "# refused: ") {
				t.Fatalf("refusal report = %+v, %v", out, err)
			}
		})
	}
}

func TestSigmaExportStaleSource(t *testing.T) {
	for _, field := range []string{"when", "proto", "kind", "severity", "evaluable", "enabled", "id", "rawSource"} {
		t.Run(field, func(t *testing.T) {
			rule, err := ConvertSigmaYAML([]byte(sigmaExportSource))
			if err != nil {
				t.Fatal(err)
			}
			switch field {
			case "id":
				rule.ID = ""
			case "rawSource":
				rule.RawSource = "title: Broken\ndetection: [\n"
			case "when":
				rule.When.Value = 6
			case "proto":
				rule.Proto = "modbus"
			case "kind":
				rule.Kind = "reply"
			case "severity":
				rule.Severity = "high"
			case "evaluable":
				rule.Labels["evaluable"] = "false"
			case "enabled":
				rule.Enabled = new(false)
			}
			text, err := ExportSigmaRule(rule)
			var refusal *RuleExportError
			if len(text) != 0 || !errors.As(err, &refusal) || !strings.Contains(refusal.Predicate, field) {
				t.Fatalf("stale %s = %q, %v", field, text, err)
			}
		})
	}
}

func TestSigmaDocumentRawSources(t *testing.T) {
	documents := []string{
		"# original head\ntitle: 'First'\nid: first\ndescription: |\n  Not a boundary: ---\n  ---\ndetection: {a: {unit_id: 1}, condition: a}\n# before next marker\n",
		"--- # actual second start\ntitle: Second\nid: second\ndetection: {a: {function_code: 5}, condition: a}\n...\n# before directive\n",
		"%YAML 1.1\n%TAG !e! tag:example.org,2026:\n---\ntitle: Third\nid: third\ndescription: \"line one\\n---\\nline two\"\ndetection: {a: {unit_id: [1, 2]}, condition: a}\n...\n",
	}
	for _, ending := range []string{"\n", "\r\n", "\r", "\u0085", "\u2028", "\u2029"} {
		t.Run(fmt.Sprintf("ending-%x", ending), func(t *testing.T) {
			var parts []string
			for _, doc := range documents {
				parts = append(parts, strings.ReplaceAll(doc, "\n", ending))
			}
			source := strings.Join(parts, "")
			rules, err := ConvertSigmaFile([]byte(source))
			if err != nil {
				t.Fatal(err)
			}
			if len(rules) != len(parts) {
				t.Fatalf("rules=%d", len(rules))
			}
			var joined string
			for i, rule := range rules {
				if rule.RawSource != parts[i] {
					t.Fatalf("document %d raw bytes changed\nwant %q\n got %q", i, parts[i], rule.RawSource)
				}
				text, err := ExportSigmaRule(rule)
				if err != nil || string(text) != rule.RawSource {
					t.Fatalf("raw export=%q,%v", text, err)
				}
				assertSigmaRoundTrip(t, rule, text)
				joined += rule.RawSource
			}
			if joined != source {
				t.Fatal("source stream bytes lost")
			}
			out, err := ExportSigmaRules(rules)
			if err != nil || len(out.Refusals) > 0 {
				t.Fatalf("bulk=%+v,%v", out, err)
			}
			got, err := ConvertSigmaFile(out.Text)
			if err != nil || len(got) != len(rules) {
				t.Fatalf("bulk introduced documents: %d,%v\n%s", len(got), err, out.Text)
			}
		})
	}
	for _, source := range []string{sigmaExportSource, "---\n" + sigmaExportSource, "\ufeff---\n" + sigmaExportSource} {
		rules, err := ConvertSigmaFile([]byte(source))
		if err != nil {
			t.Fatal(err)
		}
		out, err := ExportSigmaRules(rules)
		if err != nil || string(out.Text) != source {
			t.Fatalf("single raw file changed: %q, %v", out.Text, err)
		}
	}
}

func TestSigmaUTF16DocumentsCannotBeIndependentByteSlices(t *testing.T) {
	for _, order := range []binary.ByteOrder{binary.LittleEndian, binary.BigEndian} {
		encode := func(text string) []byte {
			data := make([]byte, 2)
			order.PutUint16(data, 0xfeff)
			for _, r := range utf16.Encode([]rune(text)) {
				var code [2]byte
				order.PutUint16(code[:], r)
				data = append(data, code[:]...)
			}
			return data
		}
		first, second := sigmaExportSource, "---\n"+strings.Replace(sigmaExportSource, "title: Test", "title: Second", 1)
		stream := append(encode(first), encode(second)[2:]...)
		// Only the stream has a BOM. The original second document's bytes cannot
		// be parsed alone; retaining them as RawSource would make export invalid.
		var standalone SigmaRule
		if err := yaml.Unmarshal(encode(second)[2:], &standalone); err == nil {
			t.Fatal("expected standalone UTF-16 without a BOM to fail")
		}
		rules, err := ConvertSigmaFile(stream)
		if err != nil || len(rules) != 2 {
			t.Fatalf("UTF-16 import=%+v,%v", rules, err)
		}
		single, err := ConvertSigmaFile(encode(first))
		if err != nil {
			t.Fatal(err)
		}
		// Native rules persist as JSON. Original UTF-16 cannot survive in a
		// JSON string; normalized UTF-8 must survive the actual storage boundary.
		originalJSON, err := json.Marshal(string(encode(first)))
		if err != nil {
			t.Fatal(err)
		}
		var originalAgain string
		if err := json.Unmarshal(originalJSON, &originalAgain); err != nil {
			t.Fatal(err)
		}
		if originalAgain == string(encode(first)) {
			t.Fatal("expected JSON to replace non-UTF-8 source bytes")
		}
		stored, err := json.Marshal(single)
		if err != nil {
			t.Fatal(err)
		}
		var loaded []config.IDSRule
		if err := json.Unmarshal(stored, &loaded); err != nil {
			t.Fatal(err)
		}
		out, err := ExportSigmaRules(loaded)
		if err != nil || string(out.Text) != single[0].RawSource {
			t.Fatalf("normalized UTF-16 source changed: %q, %v", out.Text, err)
		}
		// The low-level exporter still preserves a manually supplied original
		// single source, but must not concatenate it with incompatible encodings.
		raw := single[0]
		raw.RawSource = string(encode(first))
		out, err = ExportSigmaRules([]config.IDSRule{raw})
		if err != nil || !reflect.DeepEqual(out.Text, encode(first)) {
			t.Fatalf("original single source changed: %q, %v", out.Text, err)
		}
		out, err = ExportSigmaRules(append([]config.IDSRule{raw}, rules...))
		if err != nil || len(out.Refusals) != 1 || !strings.Contains(out.Refusals[0].Reason, "encoding") {
			t.Fatalf("mixed encodings accepted: %+v, %v", out, err)
		}
		if got, err := ConvertSigmaFile(out.Text); err != nil || len(got) != len(rules) {
			t.Fatalf("mixed encoding refusal file invalid: %d,%v", len(got), err)
		}
		for _, rule := range rules {
			text, err := ExportSigmaRule(rule)
			if err != nil || string(text) != rule.RawSource {
				t.Fatalf("normalized UTF-16=%q,%v", text, err)
			}
			assertSigmaRoundTrip(t, rule, text)
		}
	}
}

func TestSigmaDocumentJoining(t *testing.T) {
	for _, prefix := range []string{"---not-a-marker: metadata\n", "\ufeff", "# leading comment\n--- # actual marker\n"} {
		// Real document markers, lookalike keys and BOMs must all compose safely,
		// including when a refusal comment block precedes the accepted documents.
		source := prefix + sigmaExportSource
		imported, err := ConvertSigmaFile([]byte(source))
		if err != nil {
			t.Fatal(err)
		}
		native := config.IDSRule{ID: "native", When: sigmaLeaf("attr.unit_id", "equals", 1)}
		for _, rules := range [][]config.IDSRule{{native, imported[0]}, {imported[0], native}, {{ID: "refused", SrcAddr: "any"}, imported[0]}} {
			out, err := ExportSigmaRules(rules)
			if err != nil {
				t.Fatal(err)
			}
			got, err := ConvertSigmaFile(out.Text)
			if err != nil || len(got) != len(rules)-len(out.Refusals) {
				t.Fatalf("joining changed documents: %d, %v\n%s", len(got), err, out.Text)
			}
		}
	}
}
