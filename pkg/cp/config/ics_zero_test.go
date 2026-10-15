// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

package config

import (
	"encoding/json"
	"reflect"
	"testing"
)

func TestICSPredicateIsZeroEveryField(t *testing.T) {
	if !(ICSPredicate{}).IsZero() {
		t.Fatal("zero predicate is not zero")
	}
	typ := reflect.TypeFor[ICSPredicate]()
	for i := range typ.NumField() {
		t.Run(typ.Field(i).Name, func(t *testing.T) {
			var p ICSPredicate
			f := reflect.ValueOf(&p).Elem().Field(i)
			switch f.Kind() {
			case reflect.String:
				f.SetString("set")
			case reflect.Bool:
				f.SetBool(true)
			case reflect.Pointer:
				// A pointer to zero is still a restriction (unit ID 0).
				f.Set(reflect.New(f.Type().Elem()))
			case reflect.Slice:
				f.Set(reflect.MakeSlice(f.Type(), 1, 1))
			default:
				t.Fatalf("add a non-zero test value for %s", f.Type())
			}
			if p.IsZero() {
				t.Fatal("IsZero ignores this field")
			}
			// Non-nil empty slices are not Go zero values either.
			if f.Kind() == reflect.Slice {
				f.Set(reflect.MakeSlice(f.Type(), 0, 0))
				if p.IsZero() {
					t.Fatal("non-nil empty slice must not be zero")
				}
			}
		})
	}
}

func TestRuleICSJSON(t *testing.T) {
	for _, tc := range []struct {
		name string
		ics  ICSPredicate
		want string
	}{
		{"zero", ICSPredicate{}, `{"id":"r","action":"ALLOW"}`},
		{"iec104", ICSPredicate{Protocol: "iec104", TypeIDs: []int{45}},
			`{"id":"r","ics":{"protocol":"iec104","typeIds":[45]},"action":"ALLOW"}`},
		{"unit zero", ICSPredicate{Protocol: "modbus", UnitID: new(uint8)},
			`{"id":"r","ics":{"protocol":"modbus","unitId":0},"action":"ALLOW"}`},
		{"non-nil empty slice", ICSPredicate{Addresses: []string{}},
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
