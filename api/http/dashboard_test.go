// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

package httpapi

import (
	"reflect"
	"testing"

	"github.com/tonylturner/containd/pkg/common/telemetry"
	dpevents "github.com/tonylturner/containd/pkg/dp/events"
)

func TestEventClassifierMatchesDashboardPredicates(t *testing.T) {
	tests := []dpevents.Event{
		{Proto: "ids", Kind: "alert"},
		{Proto: "ids", Kind: "notice"},
		{Proto: "other", Kind: "alert"},
		{Kind: "service.av.detected"},
		{Proto: "other", Kind: "service.av.block_flow"},
		{Proto: "modbus", Kind: "request", Attributes: map[string]any{"is_write": true}},
		{Proto: "modbus", Kind: "request", Attributes: map[string]any{"is_write": false}},
		{Proto: "modbus", Kind: "response", Attributes: map[string]any{"is_write": true}},
		{Proto: "other", Kind: "request", Attributes: map[string]any{"is_write": true}},
		{Proto: "modbus", Kind: "request", Attributes: map[string]any{"is_write": "true"}},
		{Proto: "modbus", Kind: "request"},
	}
	for i, event := range tests {
		got, want := dpevents.Classify(event), dashboardPredicateClasses(event)
		if !reflect.DeepEqual(got, want) {
			t.Errorf("event %d: Classify(%+v) = %v, old predicates = %v", i, event, got, want)
		}
	}
}

func dashboardPredicateClasses(e dpevents.Event) []telemetry.EventClass {
	var classes []telemetry.EventClass
	if e.Proto == "ids" && e.Kind == "alert" {
		classes = append(classes, telemetry.ClassIDSAlert)
	}
	if e.Kind == "service.av.detected" {
		classes = append(classes, telemetry.ClassAVDetection)
	}
	if e.Kind == "service.av.block_flow" {
		classes = append(classes, telemetry.ClassAVBlock)
	}
	if e.Proto == "modbus" && e.Kind == "request" {
		isWrite, ok := e.Attributes["is_write"].(bool)
		if ok && isWrite {
			classes = append(classes, telemetry.ClassModbusWrite)
		}
	}
	return classes
}
