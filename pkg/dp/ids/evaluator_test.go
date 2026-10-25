// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

package ids

import (
	"testing"

	"github.com/tonylturner/containd/pkg/dp/dpi"
	"github.com/tonylturner/containd/pkg/dp/rules"
)

func TestEvaluatorMatchesLeafOps(t *testing.T) {
	cfg := rules.IDSConfig{
		Enabled: true,
		Rules: []rules.IDSRule{
			{
				ID:    "r1",
				Proto: "modbus",
				When: rules.IDSCondition{
					Field: "attr.function_code",
					Op:    "in",
					Value: []any{float64(5), float64(6)},
				},
				Severity: "high",
				Message:  "write",
			},
		},
	}
	ev := dpi.Event{
		FlowID: "f1",
		Proto:  "modbus",
		Kind:   "request",
		Attributes: map[string]any{
			"function_code": uint8(6),
		},
	}
	out := New(cfg).Evaluate(ev)
	if len(out) != 1 || out[0].Proto != "ids" || out[0].Kind != "alert" {
		t.Fatalf("expected alert, got %+v", out)
	}
}

func TestEvaluatorNestedAllAnyNot(t *testing.T) {
	cfg := rules.IDSConfig{
		Enabled: true,
		Rules: []rules.IDSRule{
			{
				ID: "r2",
				When: rules.IDSCondition{
					All: []rules.IDSCondition{
						{Field: "proto", Op: "equals", Value: "dns"},
						{Not: &rules.IDSCondition{Field: "attr.qname", Op: "contains", Value: "internal"}},
					},
				},
			},
		},
	}
	ev := dpi.Event{Proto: "dns", Attributes: map[string]any{"qname": "example.com"}}
	if len(New(cfg).Evaluate(ev)) != 1 {
		t.Fatal("expected match")
	}
	ev2 := dpi.Event{Proto: "dns", Attributes: map[string]any{"qname": "internal.local"}}
	if len(New(cfg).Evaluate(ev2)) != 0 {
		t.Fatal("expected no match")
	}
}

func TestEvaluatorNonEvaluableRulesNeverAlert(t *testing.T) {
	enabled := true
	for _, flag := range []*bool{nil, &enabled} {
		for _, condition := range []rules.IDSCondition{{}, {Field: "proto", Value: "dns"}} {
			rule := rules.IDSRule{
				ID: "stored-only", Enabled: flag, When: condition,
				Labels: map[string]string{"evaluable": "false"},
			}
			ev := dpi.Event{Proto: "dns", Kind: "query"}
			if idsRuleMatchesEvent(rule, ev) {
				t.Fatal("non-evaluable rule matched")
			}
			if out := New(rules.IDSConfig{Enabled: true, Rules: []rules.IDSRule{rule}}).Evaluate(ev); len(out) != 0 {
				t.Fatalf("non-evaluable rule alerted: %+v", out)
			}
		}
	}
}

func TestEvaluatorNativeEmptyCondition(t *testing.T) {
	// Native kind-only signatures deliberately have no When predicate
	// (e.g. the built-in service.av.detected signature).
	for _, labels := range []map[string]string{nil, {"evaluable": "true"}} {
		rule := rules.IDSRule{ID: "native", Proto: "dns", Kind: "query", Labels: labels}
		e := New(rules.IDSConfig{Enabled: true, Rules: []rules.IDSRule{rule}})
		if out := e.Evaluate(dpi.Event{Proto: "dns", Kind: "query"}); len(out) != 1 {
			t.Fatalf("native kind-only rule no longer alerts: %+v", out)
		}
		if out := e.Evaluate(dpi.Event{Proto: "dns", Kind: "response"}); len(out) != 0 {
			t.Fatalf("kind filter ignored: %+v", out)
		}
		if out := e.Evaluate(dpi.Event{Proto: "http", Kind: "query"}); len(out) != 0 {
			t.Fatalf("protocol filter ignored: %+v", out)
		}
	}
}
