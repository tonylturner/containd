package ids

import (
	"reflect"
	"testing"

	"github.com/containd/containd/pkg/cp/config"
)

func TestConvertSigmaSimpleSelection(t *testing.T) {
	sigma := []byte(`
title: Modbus write attempt
id: sigma-mb-1
level: high
tags: [containd.proto.modbus, containd.kind.request]
detection:
  selection:
    function_code|in: [5,6,15,16]
  condition: selection
`)
	r, err := ConvertSigmaYAML(sigma)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if r.ID != "sigma-mb-1" || r.Proto != "modbus" || r.Kind != "request" {
		t.Fatalf("bad rule header: %+v", r)
	}
	// Single selection can be represented as a leaf (preferred) or as a 1-element AND.
	cond := r.When
	if len(cond.All) == 1 {
		cond = cond.All[0]
	}
	if cond.Field != "attr.function_code" || cond.Op != "in" {
		t.Fatalf("bad condition: %+v", r.When)
	}
}

func TestConditionExpressionAndOrNot(t *testing.T) {
	det := map[string]any{
		"sel1":      map[string]any{"a": 1},
		"sel2":      map[string]any{"b|contains": "x"},
		"sel3":      map[string]any{"c": []any{1, 2}},
		"condition": "sel1 and (sel2 or not sel3)",
	}
	c, err := buildDetectionConditions(det)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(c.All) != 2 {
		t.Fatalf("expected top-level and: %+v", c)
	}
	if len(c.All[1].Any) != 2 || c.All[1].Any[1].Not == nil {
		t.Fatalf("expected or/not nesting: %+v", c.All[1])
	}
}

func TestSelectionListIsOr(t *testing.T) {
	det := map[string]any{
		"selection": []any{
			map[string]any{"x": 1},
			map[string]any{"x": 2},
		},
		"condition": "selection",
	}
	c, err := buildDetectionConditions(det)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(c.Any) != 2 {
		t.Fatalf("expected OR for list selection: %+v", c)
	}
}

func TestNormalizeField(t *testing.T) {
	if got := normalizeField("Function_Code"); got != "attr.function_code" {
		t.Fatalf("normalize mismatch: %s", got)
	}
	if got := normalizeField("attr.unit_id"); got != "attr.unit_id" {
		t.Fatalf("normalize mismatch: %s", got)
	}
}

func TestMapSigmaLevel(t *testing.T) {
	if mapSigmaLevel("critical") != "critical" {
		t.Fatal("critical mapping failed")
	}
	if mapSigmaLevel("informational") != "low" {
		t.Fatal("info mapping failed")
	}
}

func TestConvertSigmaMissingCondition(t *testing.T) {
	_, err := ConvertSigmaRule(SigmaRule{
		Title: "x",
		Detection: map[string]any{
			"a": map[string]any{"x": 1},
			"b": map[string]any{"y": 2},
		},
	})
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestConvertSigmaWildcardSelection(t *testing.T) {
	det := map[string]any{
		"selection1": map[string]any{"x": 1},
		"selection2": map[string]any{"y": 2},
		"condition":  "selection*",
	}
	c, err := buildDetectionConditions(det)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(c.Any) != 2 {
		t.Fatalf("expected wildcard OR: %+v", c)
	}
}

func TestConvertSigmaEmptyDetectionsOk(t *testing.T) {
	r, err := ConvertSigmaRule(SigmaRule{Title: "x"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !reflect.DeepEqual(r.When, config.IDSCondition{}) {
		t.Fatalf("expected empty condition: %+v", r.When)
	}
}
