// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 containd Authors

package ids_test

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/tonylturner/containd/pkg/cp/compile"
	"github.com/tonylturner/containd/pkg/cp/config"
	cpids "github.com/tonylturner/containd/pkg/cp/ids"
	"github.com/tonylturner/containd/pkg/dp/dpi"
	dpids "github.com/tonylturner/containd/pkg/dp/ids"
)

// Exercise import, storage serialization, compilation and the real evaluator.
func compiledImport(t *testing.T, format, source string, dropped []string) *dpids.Evaluator {
	t.Helper()
	imported, err := cpids.ImportRules([]byte(source), format)
	if err != nil {
		t.Fatal(err)
	}
	if len(imported) != 1 {
		t.Fatalf("expected one stored rule, got %d", len(imported))
	}
	rule := imported[0]
	if len(dropped) > 0 {
		if rule.Labels["evaluable"] != "false" {
			t.Fatalf("lossy rule is evaluable: %+v", rule)
		}
		for _, keyword := range dropped {
			if !strings.Contains(strings.Join(rule.ConversionNotes, "\n"), `"`+keyword+`"`) {
				t.Errorf("missing dropped keyword %q in %v", keyword, rule.ConversionNotes)
			}
		}
	} else if rule.Labels["evaluable"] == "false" || len(rule.ConversionNotes) != 0 {
		t.Fatalf("fully converted rule was marked non-evaluable: %+v", rule)
	}

	// Explicitly enabling a rule must not override its non-evaluable status.
	enabled := true
	rule.Enabled = &enabled
	encoded, err := json.Marshal(rule)
	if err != nil {
		t.Fatal(err)
	}
	var stored config.IDSRule
	if err := json.Unmarshal(encoded, &stored); err != nil {
		t.Fatal(err)
	}
	cfg := config.DefaultConfig()
	cfg.IDS.Enabled = true
	cfg.IDS.Rules = []config.IDSRule{stored}
	snapshot, err := compile.CompileSnapshot(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if len(snapshot.IDS.Rules) != 1 {
		t.Fatal("non-evaluable rules must remain stored and compiled")
	}
	return dpids.New(snapshot.IDS)
}

func TestImportedPacketRulesFailClosed(t *testing.T) {
	tests := []struct {
		name, header, options string
		dropped               []string
	}{
		{"bare content", "", `content:"bad";`, []string{"content"}},
		{"pcre", "", `pcre:"/bad/i";`, []string{"pcre"}},
		{"byte test", "", `byte_test:1,=,3,0;`, []string{"byte_test"}},
		{"flow", "", `flow:established,to_server;`, []string{"flow"}},
		{"flowbits", "", `flowbits:isset,seen;`, []string{"flowbits"}},
		{"threshold", "", `threshold:type limit,track by_src,count 1,seconds 60;`, []string{"threshold"}},
		{"unknown", "", `future_constraint:1;`, []string{"future_constraint"}},
		{"offset", "", `content:"bad"; http_uri; offset:3;`, []string{"offset"}},
		{"depth", "", `content:"bad"; http_uri; depth:3;`, []string{"depth"}},
		{"distance", "", `content:"bad"; http_uri; distance:3;`, []string{"distance"}},
		{"within", "", `content:"bad"; http_uri; within:3;`, []string{"within"}},
		{"nocase", "", `content:"bad"; http_uri; nocase;`, []string{"nocase"}},
		{"negation", "", `content:!"bad"; http_uri;`, []string{"content"}},
		{"hex", "", `content:"|62 61 64|"; http_uri;`, []string{"content"}},
		{"mixed hex", "", `content:"ba|64|"; http_uri;`, []string{"content"}},
		{"escape", "", `content:"ba\"d"; http_uri;`, []string{"content"}},
		{"partial", "", `content:"bad"; http_uri; content:"payload";`, []string{"content"}},
		{"partial pcre", "", `content:"bad"; http_uri; pcre:"/second/";`, []string{"pcre"}},
		{"sticky before content", "", `http.uri; content:"bad";`, []string{"http.uri", "content"}},
		{"empty content", "", `content:""; http_uri;`, []string{"content"}},
		{"orphan buffer", "", `http_uri;`, []string{"http_uri"}},
		{"header buffer", "", `content:"bad"; http_header;`, []string{"http_header", "content"}},
		{"dotted header buffer", "", `content:"bad"; http.header;`, []string{"http.header", "content"}},
		{"source address", "http $HOME_NET any -> any any", "", []string{"src_addr"}},
		{"destination address", "http any any -> 192.0.2.1 any", "", []string{"dst_addr"}},
		{"source port", "http any 1234 -> any any", "", []string{"src_port"}},
		{"destination port", "tcp any any -> any 80", "", []string{"dst_port"}},
		{"snort activation", "", `activated_by:1; count:2; tag:session,5,packets;`, []string{"activated_by", "count", "tag"}},
	}
	for _, format := range []string{"suricata", "snort"} {
		t.Run(format, func(t *testing.T) {
			for _, tt := range tests {
				t.Run(tt.name, func(t *testing.T) {
					header := tt.header
					if header == "" {
						header = "http any any -> any any"
					}
					source := `alert ` + header + ` (msg:"loss test"; sid:1; ` + tt.options + `)`
					eval := compiledImport(t, format, source, tt.dropped)
					for _, ev := range []dpi.Event{
						{Proto: "http", Attributes: map[string]any{"path": "/bad", "payload": "payload"}},
						{Proto: "http", Attributes: map[string]any{"path": "/unrelated"}},
						{Proto: "dns", Kind: "query"},
					} {
						if alerts := eval.Evaluate(ev); len(alerts) != 0 {
							t.Fatalf("lossy rule alerted: %+v", alerts)
						}
					}
				})
			}
		})
	}
}

func TestImportedPacketRuleConjunction(t *testing.T) {
	for _, format := range []string{"suricata", "snort"} {
		t.Run(format, func(t *testing.T) {
			source := `alert http any any -> any any (msg:"multiple mapped"; sid:1; content:"GET"; http_method; content:"/bad!"; http_uri;)`
			eval := compiledImport(t, format, source, nil)
			for _, tt := range []struct {
				method, uri string
				alerts      int
			}{
				{"GET", "/bad!", 1},
				{"POST", "/bad!", 0},
				{"GET", "/unrelated", 0},
			} {
				ev := decodedProtocolEvent(t, "http", []byte(tt.method+" "+tt.uri+" HTTP/1.1\r\nHost: example.test\r\n\r\n"))
				if got := len(eval.Evaluate(ev)); got != tt.alerts {
					t.Fatalf("%+v: got %d alerts", tt, got)
				}
			}
		})
	}
}

func TestImportedPacketRuleWithoutLostConstraints(t *testing.T) {
	for _, format := range []string{"suricata", "snort"} {
		t.Run(format, func(t *testing.T) {
			eval := compiledImport(t, format, `alert http any any -> any any (msg:"any HTTP"; sid:1;)`, nil)
			if len(eval.Evaluate(dpi.Event{Proto: "http"})) != 1 {
				t.Fatal("intentional protocol-only rule stopped working")
			}
			if len(eval.Evaluate(dpi.Event{Proto: "dns"})) != 0 {
				t.Fatal("protocol constraint was lost")
			}
		})
	}
}

func TestImportedSigmaRulesFailClosed(t *testing.T) {
	tests := []struct {
		name, selection string
		dropped         []string
	}{
		{"unknown", `path|unknown: bad`, []string{"unknown"}},
		{"chained all", `path|contains|all: [bad, second]`, []string{"all", "contains"}},
		{"chained unknown", `path|re|future: bad`, []string{"future"}},
		{"startswith", `path|startswith: bad`, []string{"startswith"}},
		{"endswith", `path|endswith: bad`, []string{"endswith"}},
		{"regex list", `path|re: [bad, second]`, []string{"re"}},
		{"partial", "path|contains: bad\n    other|unknown: second", []string{"unknown"}},
		{"empty map", "{}", []string{"selection"}},
		{"empty list", "[]", []string{"selection"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			source := "title: Sigma loss test\ndetection:\n  selection:\n    " + tt.selection + "\n  condition: selection\n"
			eval := compiledImport(t, "sigma", source, tt.dropped)
			for _, attrs := range []map[string]any{
				{"path": "bad", "other": "second"},
				{"path": "unrelated", "other": "second"},
				nil,
			} {
				if alerts := eval.Evaluate(dpi.Event{Proto: "http", Attributes: attrs}); len(alerts) != 0 {
					t.Fatalf("lossy Sigma rule alerted: %+v", alerts)
				}
			}
		})
	}
	t.Run("empty detection", func(t *testing.T) {
		eval := compiledImport(t, "sigma", "title: Empty\n", []string{"detection"})
		if alerts := eval.Evaluate(dpi.Event{Proto: "dns"}); len(alerts) != 0 {
			t.Fatal("empty detection alerted")
		}
	})
}

func TestImportedSigmaUnmappedCondition(t *testing.T) {
	for _, condition := range []string{"1", "'1'", "42", "'42'", "all", "selection |", "selection!", "[]", "''"} {
		t.Run(condition, func(t *testing.T) {
			source := "title: Unmapped condition\ndetection:\n  selection:\n    path: bad\n  condition: " + condition + "\n"
			eval := compiledImport(t, "sigma", source, []string{"condition"})
			if alerts := eval.Evaluate(dpi.Event{Attributes: map[string]any{"path": "bad"}}); len(alerts) != 0 {
				t.Fatal("unmapped condition alerted")
			}
		})
	}
}

func TestImportedSigmaRulesKeepMappedConstraints(t *testing.T) {
	for _, selection := range []string{
		`path: bad`, `path|contains: bad`, `path|re: "^bad$"`,
		`path|regex: "^bad$"`, `path: [bad, second]`, `path|in: [bad, second]`,
	} {
		t.Run(selection, func(t *testing.T) {
			source := "title: Mapped Sigma\ndetection:\n  selection:\n    " + selection + "\n  condition: selection\n"
			eval := compiledImport(t, "sigma", source, nil)
			if alerts := eval.Evaluate(dpi.Event{Attributes: map[string]any{"path": "bad"}}); len(alerts) != 1 {
				t.Fatal("mapped Sigma rule did not alert")
			}
			if alerts := eval.Evaluate(dpi.Event{Attributes: map[string]any{"path": "unrelated"}}); len(alerts) != 0 {
				t.Fatal("mapped Sigma rule broadened")
			}
		})
	}
}
