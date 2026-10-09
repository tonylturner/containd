// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

package config

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"
)

func decodeICS(t *testing.T, in string) (ICSPredicate, error) {
	t.Helper()
	var pred ICSPredicate
	err := json.Unmarshal([]byte(in), &pred)
	return pred, err
}

func TestICSPredicateStrictDecodeRejects(t *testing.T) {
	cases := []struct {
		name, in, want string
	}{
		{"unknown key", `{"protocol":"modbus","functionCodes":[3]}`, `unknown key "functionCodes"`},
		{"case variant is unknown", `{"Protocol":"modbus"}`, `unknown key "Protocol"`},
		{"duplicate key", `{"protocol":"modbus","protocol":"dnp3"}`, `duplicate key "protocol"`},
		{"duplicate new key", `{"protocol":"iec104","ca":[1],"ca":[2]}`, `duplicate key "ca"`},
		{"not an object", `["iec104"]`, "expected a JSON object"},

		{"typeIds null", `{"protocol":"iec104","typeIds":null}`, "typeIds: must not be null"},
		{"typeIds empty", `{"protocol":"iec104","typeIds":[]}`, "typeIds: must not be empty"},
		{"classes null", `{"protocol":"iec104","classes":null}`, "classes: must not be null"},
		{"classes empty", `{"protocol":"iec104","classes":[]}`, "classes: must not be empty"},
		{"ca null", `{"protocol":"iec104","ca":null}`, "ca: must not be null"},
		{"ca empty", `{"protocol":"iec104","ca":[]}`, "ca: must not be empty"},
		{"ioa null", `{"protocol":"iec104","ioa":null}`, "ioa: must not be null"},
		{"ioa empty", `{"protocol":"iec104","ioa":[]}`, "ioa: must not be empty"},
		{"null element", `{"protocol":"iec104","ca":[1,null]}`, "ca: item 1 must not be null"},
		{"null ioa element", `{"protocol":"iec104","ioa":[null]}`, "ioa: item 0 must not be null"},

		{"typeIds fraction", `{"protocol":"iec104","typeIds":[45.5]}`, "typeIds: item 0"},
		{"typeIds string", `{"protocol":"iec104","typeIds":["46"]}`, "typeIds: item 0"},
		{"typeIds not a list", `{"protocol":"iec104","typeIds":46}`, "ics typeIds"},
		{"ca fraction", `{"protocol":"iec104","ca":[1.5]}`, "ca: item 0"},
		{"ca overflow", `{"protocol":"iec104","ca":[65536]}`, "ca: item 0"},
		{"ca negative", `{"protocol":"iec104","ca":[-1]}`, "ca: item 0"},
		{"ioa fraction", `{"protocol":"iec104","ioa":[{"start":1.5,"end":2}]}`, `range "start"`},
		{"ioa overflow", `{"protocol":"iec104","ioa":[{"start":0,"end":4294967296}]}`, `range "end"`},
		{"ioa missing end", `{"protocol":"iec104","ioa":[{"start":0}]}`, `range needs "end"`},
		{"ioa missing start", `{"protocol":"iec104","ioa":[{"end":0}]}`, `range needs "start"`},
		{"ioa null endpoint", `{"protocol":"iec104","ioa":[{"start":null,"end":1}]}`, `range "start" must not be null`},
		{"ioa unknown key", `{"protocol":"iec104","ioa":[{"start":0,"end":1,"step":1}]}`, `unknown key "step"`},
		{"ioa duplicate key", `{"protocol":"iec104","ioa":[{"start":0,"end":1,"end":2}]}`, `duplicate key "end"`},

		{"iec104 writeOnly false", `{"protocol":"iec104","writeOnly":false}`, "writeOnly is not supported for protocol iec104"},
		{"iec104 functionCode null", `{"protocol":"iec104","functionCode":null}`, "functionCode is not supported for protocol iec104"},
		{"iec104 unitId", `{"protocol":"iec104","unitId":1}`, "unitId is not supported for protocol iec104"},
		{"iec104 addresses empty", `{"protocol":"iec104","addresses":[]}`, "addresses is not supported for protocol iec104"},
		{"iec104 objectClasses", `{"protocol":"iec104","objectClasses":[1]}`, "objectClasses is not supported for protocol iec104"},
		{"modbus typeIds", `{"protocol":"modbus","typeIds":[46]}`, "typeIds is only supported for protocol iec104"},
		{"dnp3 ioa", `{"protocol":"dnp3","ioa":[{"start":1,"end":1}]}`, "ioa is only supported for protocol iec104"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := decodeICS(t, tc.in)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("decode %s: err = %v, want it to contain %q", tc.in, err, tc.want)
			}
		})
	}
}

func TestICSPredicateStrictDecodeAccepts(t *testing.T) {
	cases := []struct {
		name, in string
		want     ICSPredicate
	}{
		{"empty object", `{}`, ICSPredicate{}},
		{"json null", `null`, ICSPredicate{}},
		{"functionCode null", `{"protocol":"modbus","functionCode":null}`, ICSPredicate{Protocol: "modbus"}},
		{"functionCode single int", `{"protocol":"modbus","functionCode":3}`, ICSPredicate{Protocol: "modbus", FunctionCode: []uint8{3}}},
		{"functionCode string list", `{"protocol":"modbus","functionCode":["3"," 16"]}`, ICSPredicate{Protocol: "modbus", FunctionCode: []uint8{3, 16}}},
		{"functionCode string-keyed strings", `{"protocol":"modbus","functionCode":{"0":"3","1":""}}`, ICSPredicate{Protocol: "modbus", FunctionCode: []uint8{3}}},
		{"functionCode base64", `{"protocol":"modbus","functionCode":"AxA="}`, ICSPredicate{Protocol: "modbus", FunctionCode: []uint8{3, 16}}},
		{"modbus writeOnly false", `{"protocol":"modbus","writeOnly":false,"readOnly":false}`, ICSPredicate{Protocol: "modbus"}},
		{"ioa zero and above 16 bits", `{"protocol":"iec104","ioa":[{"start":0,"end":0},{"end":65536,"start":65536}]}`,
			ICSPredicate{Protocol: "iec104", IOA: []IOARange{{Start: 0, End: 0}, {Start: 65536, End: 65536}}}},
		{"iec104 readOnly false", `{"protocol":"iec104","readOnly":false,"mode":"learn"}`, ICSPredicate{Protocol: "iec104", Mode: "learn"}},
		{"spec §6.1 example", `{"protocol":"iec104","typeIds":[46],"classes":["control"],"direction":"request","ca":[1],"ioa":[{"start":65536,"end":65567}],"readOnly":false,"mode":"enforce"}`,
			ICSPredicate{Protocol: "iec104", TypeIDs: []int{46}, Classes: []string{"control"}, Direction: "request", CA: []uint16{1}, IOA: []IOARange{{Start: 65536, End: 65567}}, Mode: "enforce"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := decodeICS(t, tc.in)
			if err != nil {
				t.Fatalf("decode %s: %v", tc.in, err)
			}
			if !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("decode %s = %+v, want %+v", tc.in, got, tc.want)
			}
		})
	}
}

// The strict predicate decoder runs inside a whole config, and a JSON null
// predicate resets an earlier value.
func TestICSPredicateStrictDecodeInsideRule(t *testing.T) {
	var r Rule
	err := json.Unmarshal([]byte(`{"id":"r","action":"ALLOW","ics":{"protocol":"iec104","writeOnly":false}}`), &r)
	if err == nil || !strings.Contains(err.Error(), "writeOnly") {
		t.Fatalf("rule decode err = %v, want writeOnly rejection", err)
	}
	pred := ICSPredicate{Protocol: "modbus"}
	if err := json.Unmarshal([]byte(`null`), &pred); err != nil || !reflect.DeepEqual(pred, ICSPredicate{}) {
		t.Fatalf("null predicate = %+v, %v; want empty", pred, err)
	}
}
