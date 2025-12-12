package ids

import (
	"testing"

	"github.com/containd/containd/pkg/dp/dpi"
	"github.com/containd/containd/pkg/dp/rules"
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

