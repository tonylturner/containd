// SPDX-License-Identifier: Apache-2.0

package config

import (
	"encoding/json"
	"fmt"
	"reflect"
	"slices"
	"strings"
	"testing"
)

var selectorExamples = []struct {
	protocol, key, value string
}{
	{"iec104", "cot", "[1,63]"},
	{"iec104", "originators", "[0,255]"},
	{"iec104", "negative", "false"},
	{"iec104", "test", "false"},
	{"iec104", "selectExecute", `"execute"`},
	{"dnp3", "masters", "[0,65519]"},
	{"dnp3", "outstations", "[0,65519]"},
	{"dnp3", "groups", "[0,255]"},
	{"dnp3", "variations", "[0,255]"},
	{"cip", "instances", "[0,65535]"},
	{"cip", "attributes", "[0,65535]"},
	{"cip", "tags", `["Program:Main.A_b.Tag0"]`},
}

func TestICSSelectorJSON(t *testing.T) {
	for _, field := range selectorExamples {
		t.Run(field.key, func(t *testing.T) {
			body := fmt.Sprintf(`{"protocol":%q,%q:%s}`, field.protocol, field.key, field.value)
			var p ICSPredicate
			if err := json.Unmarshal([]byte(body), &p); err != nil {
				t.Fatal(err)
			}
			if err := ValidateICSPredicate(p, "selector"); err != nil {
				t.Fatal(err)
			}
			raw, err := json.Marshal(p)
			if err != nil {
				t.Fatal(err)
			}
			var fields map[string]json.RawMessage
			if err := json.Unmarshal(raw, &fields); err != nil {
				t.Fatal(err)
			}
			if string(fields[field.key]) != field.value {
				t.Fatalf("marshal lost %s: %s", field.key, raw)
			}
			var copy ICSPredicate
			if err := json.Unmarshal(raw, &copy); err != nil || !reflect.DeepEqual(p, copy) {
				t.Fatalf("round trip: %+v %v", copy, err)
			}
			for _, bad := range []string{"null", "[]", "[null]"} {
				err := json.Unmarshal([]byte(fmt.Sprintf(`{"protocol":%q,%q:%s}`, field.protocol, field.key, bad)), &copy)
				if err == nil || !strings.Contains(err.Error(), field.key) {
					t.Fatalf("accepted %s=%s: %v", field.key, bad, err)
				}
			}
			for _, protocol := range []string{"modbus", "dnp3", "cip", "iec104"} {
				if protocol == field.protocol {
					continue
				}
				err := json.Unmarshal([]byte(fmt.Sprintf(`{"protocol":%q,%q:%s}`, protocol, field.key, field.value)), &copy)
				if err == nil || !strings.Contains(err.Error(), field.key) {
					t.Fatalf("%s accepted %s: %v", protocol, field.key, err)
				}
				p.Protocol = protocol
				if err := ValidateICSPredicate(p, "selector"); err == nil || !strings.Contains(err.Error(), field.key) {
					t.Fatalf("Go %s accepted %s: %v", protocol, field.key, err)
				}
			}
			p.Protocol = ""
			if err := ValidateICSPredicate(p, "selector"); err == nil || !strings.Contains(err.Error(), field.key) {
				t.Fatalf("missing protocol: %v", err)
			}
		})
	}
}

func TestICSJSONKeyCoverage(t *testing.T) {
	// Guard the strict allowlist and marshal DTO against silently dropped fields.
	typ := reflect.TypeFor[ICSPredicate]()
	if typ.NumField() != len(icsPredicateKeys) {
		t.Fatalf("%d fields but %d JSON keys", typ.NumField(), len(icsPredicateKeys))
	}
	dto := reflect.TypeFor[icsPredicateJSON]()
	for i := range typ.NumField() {
		field := typ.Field(i)
		key, _, _ := strings.Cut(field.Tag.Get("json"), ",")
		if !slices.Contains(icsPredicateKeys, key) {
			t.Fatalf("%s missing from strict keys", key)
		}
		marshaled, ok := dto.FieldByName(field.Name)
		if !ok || marshaled.Tag != field.Tag {
			t.Fatalf("%s missing or renamed in marshal DTO", field.Name)
		}
	}
}

func TestICSNullPatchEveryKnownKey(t *testing.T) {
	for _, key := range icsPredicateKeys {
		t.Run(key, func(t *testing.T) {
			// All keys, including ones forbidden on this protocol, are deletions.
			got, err := PatchICSPredicate(ICSPredicate{Protocol: "modbus"}, []byte(fmt.Sprintf(`{%q:null}`, key)))
			want := ICSPredicate{Protocol: "modbus"}
			if key == "protocol" {
				want = ICSPredicate{}
			}
			if err != nil || !reflect.DeepEqual(got, want) {
				t.Fatalf("clear %s: %+v %v", key, got, err)
			}
		})
	}
	for _, field := range selectorExamples {
		var p ICSPredicate
		if err := json.Unmarshal([]byte(fmt.Sprintf(`{"protocol":%q,%q:%s}`, field.protocol, field.key, field.value)), &p); err != nil {
			t.Fatal(err)
		}
		got, err := PatchICSPredicate(p, []byte(fmt.Sprintf(`{%q:null}`, field.key)))
		if err != nil || !reflect.DeepEqual(got, ICSPredicate{Protocol: field.protocol}) {
			t.Fatalf("populated %s did not clear: %+v %v", field.key, got, err)
		}
	}
	got, err := PatchICSPredicate(ICSPredicate{Protocol: "cip", Tags: []string{"Old"}},
		[]byte(`{"protocol":"iec104","tags":null,"unitId":null,"typeIds":null,"negative":false,"originators":[0]}`))
	want := ICSPredicate{Protocol: "iec104", Negative: new(false), Originators: []int{0}}
	if err != nil || !reflect.DeepEqual(got, want) {
		t.Fatalf("protocol replacement must delete nulls first: %+v %v", got, err)
	}
	if _, err := PatchICSPredicate(got, []byte(`{"unknown":null}`)); err == nil {
		t.Fatal("null bypassed the unknown-key check")
	}
}

func TestICSSelectorValidation(t *testing.T) {
	tests := []struct {
		p     ICSPredicate
		field string
	}{
		{ICSPredicate{Protocol: "iec104", COT: []int{}}, "cot"},
		{ICSPredicate{Protocol: "iec104", COT: []int{0}}, "cot"},
		{ICSPredicate{Protocol: "iec104", COT: []int{64}}, "cot"},
		{ICSPredicate{Protocol: "iec104", Originators: []int{}}, "originators"},
		{ICSPredicate{Protocol: "iec104", Originators: []int{-1}}, "originators"},
		{ICSPredicate{Protocol: "iec104", Originators: []int{256}}, "originators"},
		{ICSPredicate{Protocol: "iec104", SelectExecute: "both"}, "selectExecute"},
		{ICSPredicate{Protocol: "dnp3", Masters: []uint16{}}, "masters"},
		{ICSPredicate{Protocol: "dnp3", Masters: []uint16{65520}}, "masters"},
		{ICSPredicate{Protocol: "dnp3", Outstations: []uint16{}}, "outstations"},
		{ICSPredicate{Protocol: "dnp3", Outstations: []uint16{65535}}, "outstations"},
		{ICSPredicate{Protocol: "dnp3", Groups: []int{}}, "groups"},
		{ICSPredicate{Protocol: "dnp3", Groups: []int{-1}}, "groups"},
		{ICSPredicate{Protocol: "dnp3", Groups: []int{256}}, "groups"},
		{ICSPredicate{Protocol: "dnp3", Variations: []int{}}, "variations"},
		{ICSPredicate{Protocol: "dnp3", Variations: []int{-1}}, "variations"},
		{ICSPredicate{Protocol: "dnp3", Variations: []int{256}}, "variations"},
		{ICSPredicate{Protocol: "cip", Instances: []uint16{}}, "instances"},
		{ICSPredicate{Protocol: "cip", Attributes: []uint16{}}, "attributes"},
		{ICSPredicate{Protocol: "cip", Tags: []string{}}, "tags"},
		{ICSPredicate{Protocol: "cip", Tags: []string{"Tag"}, ObjectClasses: []uint16{0}}, "tags"},
		{ICSPredicate{Protocol: "cip", Tags: []string{"Tag"}, Instances: []uint16{0}}, "tags"},
		{ICSPredicate{Protocol: "cip", Tags: []string{"Tag"}, Attributes: []uint16{0}}, "tags"},
	}
	for _, tc := range tests {
		err := ValidateICSPredicate(tc.p, "invalid")
		if err == nil || !strings.Contains(err.Error(), tc.field) || !strings.Contains(err.Error(), "rule invalid") {
			t.Errorf("%+v: %v (want %s)", tc.p, err, tc.field)
		}
	}
	for _, id := range []int{1, 44, 51, 57, 64, 100, 255} {
		err := ValidateICSPredicate(ICSPredicate{Protocol: "iec104", TypeIDs: []int{45, id}, SelectExecute: "select"}, "se")
		if err == nil || !strings.Contains(err.Error(), "selectExecute") {
			t.Fatalf("S/E accepted type %d: %v", id, err)
		}
	}
	for _, ids := range [][]int{nil, {45, 46, 47, 48, 49, 50, 58, 59, 60, 61, 62, 63}} {
		for _, se := range []string{"select", "execute"} {
			if err := ValidateICSPredicate(ICSPredicate{Protocol: "iec104", TypeIDs: ids, SelectExecute: se}, "se"); err != nil {
				t.Fatal(err)
			}
		}
	}
	for _, tag := range []string{"A", "_0.Member", "Program:Main.Tag", strings.Repeat("a", 40)} {
		if err := ValidateICSPredicate(ICSPredicate{Protocol: "cip", Tags: []string{tag}}, "tag"); err != nil {
			t.Fatal(err)
		}
	}
	for _, tag := range []string{"", ".A", "A.", "A..B", "1A", "A[0]", "A B", "A.Program:Main", "Program:", "Program:1A.Tag", "Program:A[0].Tag", strings.Repeat("a", 41), "é"} {
		err := ValidateICSPredicate(ICSPredicate{Protocol: "cip", Tags: []string{tag}}, "tag")
		if err == nil || !strings.Contains(err.Error(), "tags") {
			t.Fatalf("accepted tag %q: %v", tag, err)
		}
	}
}

func TestICSUnitIDSemanticValidation(t *testing.T) {
	for _, protocol := range []string{"dnp3", "cip"} {
		for _, unit := range []uint8{0, 255} {
			var decoded ICSPredicate
			if err := json.Unmarshal([]byte(fmt.Sprintf(`{"protocol":%q,"unitId":%d}`, protocol, unit)), &decoded); err != nil {
				t.Fatalf("stored unitId must remain decodable: %v", err)
			}
			for _, p := range []ICSPredicate{decoded, {Protocol: protocol, UnitID: &unit}} {
				err := ValidateICSPredicate(p, "unit")
				if err == nil || !strings.Contains(err.Error(), "unitId") {
					t.Fatalf("semantic unitId validation bypassed: %v", err)
				}
			}
			cleared, err := PatchICSPredicate(decoded, []byte(`{"unitId":null}`))
			if err != nil || ValidateICSPredicate(cleared, "unit") != nil {
				t.Fatalf("cannot repair unitId: %+v %v", cleared, err)
			}
		}
	}
}

func TestDNP3GroupedAddresses(t *testing.T) {
	for _, spec := range []string{"0", "0-4294967295", "0x0-0xffffffff"} {
		p := ICSPredicate{Protocol: "dnp3", Groups: []int{0}, Addresses: []string{spec}}
		if err := ValidateICSPredicate(p, "point"); err != nil {
			t.Fatal(err)
		}
	}
	for _, spec := range []string{"4294967296", "-1", "4-3", "0x100000000"} {
		p := ICSPredicate{Protocol: "dnp3", Groups: []int{1}, Addresses: []string{spec}}
		if err := ValidateICSPredicate(p, "point"); err == nil || !strings.Contains(err.Error(), "addresses") {
			t.Fatalf("accepted %s: %v", spec, err)
		}
	}
}
