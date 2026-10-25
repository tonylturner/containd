// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

package ids

import (
	"reflect"
	"testing"

	"github.com/tonylturner/containd/pkg/cp/config"
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
	if r.Labels["evaluable"] == "false" {
		t.Fatalf("decoder-backed ICS field must stay evaluable: %v", r.ConversionNotes)
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
		"sel1":      map[string]any{"function_code": 1},
		"sel2":      map[string]any{"path|contains": "x"},
		"sel3":      map[string]any{"unit_id": []any{1, 2}},
		"condition": "sel1 and (sel2 or not sel3)",
	}
	c, notes, err := buildDetectionConditions(det)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(notes) != 0 {
		t.Fatalf("fully mapped conditions: %v", notes)
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
			map[string]any{"unit_id": 1},
			map[string]any{"unit_id": 2},
		},
		"condition": "selection",
	}
	c, notes, err := buildDetectionConditions(det)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(notes) != 0 {
		t.Fatalf("fully mapped conditions: %v", notes)
	}
	if len(c.Any) != 2 {
		t.Fatalf("expected OR for list selection: %+v", c)
	}
}

func TestNormalizeField(t *testing.T) {
	for _, tt := range []struct {
		source, field string
	}{
		{"Function_Code", "attr.function_code"},
		{"attr.unit_id", "attr.unit_id"},
		{" HTTP_URI ", "attr.path"},
		{"attr.http_uri", "attr.path"},
		{"http_method", "attr.method"},
		{"http_host", "attr.host"},
		{"http_user_agent", "attr.user_agent"},
		{"dns_query", "attr.qname"},
		{"attr.tls_sni", "attr.sni"},
		{"SrcPort", "attr.src_port"},
		{"attr.dstport", "attr.dst_port"},
		{"Proto", "proto"},
		{"kind", "kind"},
		{"FlowID", "flowid"},
		{"srcip", ""},
		{"dstip", ""},
		{"attr.src_ip", ""},
		{"attr.proto", ""},
		{"http_header", ""},
		{"attr.http_header", ""},
		{"unknown", ""},
		{"attr.unknown", ""},
		{"", ""},
	} {
		t.Run(tt.source, func(t *testing.T) {
			if got := normalizeField(tt.source); got != tt.field {
				t.Fatalf("normalize = %q, want %q", got, tt.field)
			}
		})
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
		"selection1": map[string]any{"unit_id": 1},
		"selection2": map[string]any{"function_code": 2},
		"condition":  "selection*",
	}
	c, notes, err := buildDetectionConditions(det)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(notes) != 0 {
		t.Fatalf("fully mapped conditions: %v", notes)
	}
	if len(c.Any) != 2 {
		t.Fatalf("expected wildcard OR: %+v", c)
	}
}

func TestConvertSigmaEmptyDetectionStoredNonEvaluable(t *testing.T) {
	r, err := ConvertSigmaRule(SigmaRule{Title: "x"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !reflect.DeepEqual(r.When, config.IDSCondition{}) {
		t.Fatalf("expected empty condition: %+v", r.When)
	}
	if r.Labels["evaluable"] != "false" || len(r.ConversionNotes) == 0 {
		t.Fatalf("empty detection must be stored as non-evaluable: %+v", r)
	}
}
