// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

package config

import (
	"bytes"
	"encoding/json"
	"reflect"
	"testing"
)

func TestRuleICSJSON(t *testing.T) {
	for _, tc := range []struct {
		name string
		ics  ICSPredicate
		want string
	}{
		{"zero", ICSPredicate{}, `{"id":"r","ics":{},"action":"ALLOW"}`},
		{"iec104", ICSPredicate{Protocol: "iec104", TypeIDs: []int{45}},
			`{"id":"r","ics":{"protocol":"iec104","typeIds":[45]},"action":"ALLOW"}`},
		{"unit zero", ICSPredicate{Protocol: "modbus", UnitID: new(uint8)},
			`{"id":"r","ics":{"protocol":"modbus","unitId":0},"action":"ALLOW"}`},
		{"non-nil empty slice", ICSPredicate{Addresses: []string{}},
			`{"id":"r","ics":{},"action":"ALLOW"}`},
		{"all empty slices", ICSPredicate{FunctionCode: []uint8{}, Addresses: []string{},
			ObjectClasses: []uint16{}, TypeIDs: []int{}, Classes: []string{}, CA: []uint16{}, IOA: []IOARange{}},
			`{"id":"r","ics":{},"action":"ALLOW"}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := json.Marshal(Rule{ID: "r", Action: "ALLOW", ICS: tc.ics})
			if err != nil || string(got) != tc.want {
				t.Fatalf("Marshal = %s, %v; want %s", got, err, tc.want)
			}
		})
	}
}

func TestRuleICSPredicateRoundTripUnchanged(t *testing.T) {
	const input = `{"id":"r","ics":{"protocol":"iec104","typeIds":[45],"classes":["control"],"ca":[1],"ioa":[{"start":12,"end":34}],"direction":"response","mode":"enforce"},"action":"ALLOW"}`
	var rule Rule
	if err := json.Unmarshal([]byte(input), &rule); err != nil {
		t.Fatal(err)
	}
	got, err := json.Marshal(rule)
	if err != nil {
		t.Fatal(err)
	}
	var canonicalInput, canonicalGot any
	if err := json.Unmarshal([]byte(input), &canonicalInput); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(got, &canonicalGot); err != nil {
		t.Fatal(err)
	}
	want, err := json.Marshal(canonicalInput)
	if err != nil {
		t.Fatal(err)
	}
	canonical, err := json.Marshal(canonicalGot)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(canonical, want) {
		t.Fatalf("rule changed on round trip:\n got %s\nwant %s", canonical, want)
	}
}

func TestRuleICSRoundTrip(t *testing.T) {
	for _, input := range []string{
		`{"id":"r","action":"ALLOW"}`,
		`{"id":"r","ics":null,"action":"ALLOW"}`,
		`{"id":"r","ics":{},"action":"ALLOW"}`,
		`{"id":"r","ics":{"protocol":"iec104","typeIds":[45]},"action":"ALLOW"}`,
		`{"id":"r","ics":{"protocol":"modbus","functionCode":[3],"unitId":0},"action":"ALLOW"}`,
	} {
		t.Run(input, func(t *testing.T) {
			var before, after Rule
			if err := json.Unmarshal([]byte(input), &before); err != nil {
				t.Fatal(err)
			}
			body, err := json.Marshal(before)
			if err != nil {
				t.Fatal(err)
			}
			if err := json.Unmarshal(body, &after); err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(before, after) {
				t.Fatalf("round trip changed rule: %+v -> %+v", before, after)
			}
		})
	}
}
