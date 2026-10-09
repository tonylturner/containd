// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

// Package eventfieldstest holds test helpers for decoders that emit
// eventfields attributes.
package eventfieldstest

import (
	"bytes"
	"encoding/json"
	"testing"
)

// Forms returns attrs as a decoder emitted them, after a JSON round trip
// into map[string]any (float64 numbers), and after one with UseNumber
// (json.Number). The strict eventfields accessors must read all three.
func Forms(t testing.TB, attrs map[string]any) map[string]map[string]any {
	t.Helper()
	body, err := json.Marshal(attrs)
	if err != nil {
		t.Fatalf("marshal attributes: %v", err)
	}
	var plain map[string]any
	if err := json.Unmarshal(body, &plain); err != nil {
		t.Fatalf("unmarshal attributes: %v", err)
	}
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.UseNumber()
	var numbers map[string]any
	if err := dec.Decode(&numbers); err != nil {
		t.Fatalf("decode attributes with UseNumber: %v", err)
	}
	return map[string]map[string]any{"memory": attrs, "json": plain, "json.Number": numbers}
}
