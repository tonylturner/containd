// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

package config

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"
)

func TestICSPredicateMarshalJSONUsesNumericArray(t *testing.T) {
	unitID := uint8(7)
	pred := ICSPredicate{
		Protocol:      "modbus",
		FunctionCode:  []uint8{3, 16},
		UnitID:        &unitID,
		Addresses:     []string{"0-10"},
		ObjectClasses: []uint16{2, 4},
		ReadOnly:      true,
		Mode:          "enforce",
	}

	body, err := json.Marshal(pred)
	if err != nil {
		t.Fatalf("MarshalJSON: %v", err)
	}

	text := string(body)
	if strings.Contains(text, `"functionCode":"`) {
		t.Fatalf("functionCode must not be encoded as base64: %s", text)
	}
	if !strings.Contains(text, `"functionCode":[3,16]`) {
		t.Fatalf("functionCode must be encoded as a numeric array: %s", text)
	}
}

func TestICSPredicateUnmarshalJSONAcceptsLegacyBase64AndArrayForms(t *testing.T) {
	t.Run("legacy base64", func(t *testing.T) {
		var pred ICSPredicate
		if err := json.Unmarshal([]byte(`{"protocol":"modbus","functionCode":"AQMQ"}`), &pred); err != nil {
			t.Fatalf("Unmarshal legacy base64: %v", err)
		}
		if want := []uint8{1, 3, 16}; !reflect.DeepEqual(pred.FunctionCode, want) {
			t.Fatalf("unexpected legacy decoded function codes: got %v want %v", pred.FunctionCode, want)
		}
	})

	t.Run("numeric array", func(t *testing.T) {
		var pred ICSPredicate
		if err := json.Unmarshal([]byte(`{"protocol":"modbus","functionCode":[3,16]}`), &pred); err != nil {
			t.Fatalf("Unmarshal numeric array: %v", err)
		}
		if want := []uint8{3, 16}; !reflect.DeepEqual(pred.FunctionCode, want) {
			t.Fatalf("unexpected function codes: got %v want %v", pred.FunctionCode, want)
		}
	})

	t.Run("numeric-keyed object", func(t *testing.T) {
		var pred ICSPredicate
		if err := json.Unmarshal([]byte(`{"protocol":"modbus","functionCode":{"1":16,"0":3}}`), &pred); err != nil {
			t.Fatalf("Unmarshal numeric-keyed object: %v", err)
		}
		if want := []uint8{3, 16}; !reflect.DeepEqual(pred.FunctionCode, want) {
			t.Fatalf("unexpected function codes: got %v want %v", pred.FunctionCode, want)
		}
	})
}
