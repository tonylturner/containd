// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

package config

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"
)

func TestPatchICSPredicate(t *testing.T) {
	modbus := ICSPredicate{Protocol: "modbus", FunctionCode: []uint8{3, 16}, WriteOnly: true, Mode: "enforce"}
	iec := ICSPredicate{Protocol: "iec104", TypeIDs: []int{46}, CA: []uint16{1}, Mode: "enforce"}
	cases := []struct {
		name  string
		cur   ICSPredicate
		patch string
		want  ICSPredicate
	}{
		{"protocol change replaces", modbus, `{"protocol":"iec104","classes":["control"]}`,
			ICSPredicate{Protocol: "iec104", Classes: []string{"control"}}},
		{"same protocol merges", iec, `{"protocol":"iec104","ioa":[{"start":2001,"end":2001}]}`,
			ICSPredicate{Protocol: "iec104", TypeIDs: []int{46}, CA: []uint16{1}, IOA: []IOARange{{Start: 2001, End: 2001}}, Mode: "enforce"}},
		{"merge replaces a list", iec, `{"typeIds":[45,46]}`,
			ICSPredicate{Protocol: "iec104", TypeIDs: []int{45, 46}, CA: []uint16{1}, Mode: "enforce"}},
		{"functionCode null clears on modbus", modbus, `{"functionCode":null}`,
			ICSPredicate{Protocol: "modbus", WriteOnly: true, Mode: "enforce"}},
		{"generic null clears all optional selectors", ICSPredicate{Protocol: "modbus", FunctionCode: []uint8{3}, UnitID: new(uint8(1)), Addresses: []string{"0-10"}, ReadOnly: true, Direction: "request"},
			`{"functionCode":null,"unitId":null,"addresses":null,"readOnly":null,"direction":null}`,
			ICSPredicate{Protocol: "modbus"}},
		{"CIP classes null clears", ICSPredicate{Protocol: "cip", ObjectClasses: []uint16{4}, WriteOnly: true},
			`{"objectClasses":null,"writeOnly":null}`, ICSPredicate{Protocol: "cip"}},
		{"generic omitted selectors stay", modbus, `{}`, modbus},
		{"empty patch keeps", iec, `{}`, iec},
		{"IEC null clears", iec, `{"typeIds":null,"ca":null}`, ICSPredicate{Protocol: "iec104", Mode: "enforce"}},
		{"null clears", iec, `null`, ICSPredicate{}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := PatchICSPredicate(tc.cur, json.RawMessage(tc.patch))
			if err != nil {
				t.Fatalf("patch %s: %v", tc.patch, err)
			}
			if !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("patch %s = %+v, want %+v", tc.patch, got, tc.want)
			}
		})
	}

	rejects := []struct {
		name  string
		cur   ICSPredicate
		patch string
		want  string
	}{
		{"duplicate key in patch", iec, `{"ca":[1],"ca":[2]}`, `duplicate key "ca"`},
		{"unknown key in patch", iec, `{"typeID":[46]}`, `unknown key "typeID"`},
		{"writeOnly false merged into iec104", iec, `{"writeOnly":false}`, "writeOnly is not supported for protocol iec104"},
		{"modbus fields kept on iec104 merge", modbus, `{"protocol":"modbus","typeIds":[46]}`, "typeIds is only supported for protocol iec104"},
	}
	for _, tc := range rejects {
		t.Run(tc.name, func(t *testing.T) {
			_, err := PatchICSPredicate(tc.cur, json.RawMessage(tc.patch))
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("patch %s: err = %v, want %q", tc.patch, err, tc.want)
			}
		})
	}
}
