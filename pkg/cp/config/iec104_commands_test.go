// SPDX-License-Identifier: Apache-2.0
package config

import (
	"encoding/json"
	"fmt"
	"reflect"
	"testing"
)

func TestIEC104CommandPredicates(t *testing.T) {
	for _, tc := range []struct {
		fields string
		valid  bool
	}{
		{`"typeIds":[45,58],"commandStates":[0,1],"commandQualifiers":[0,31]`, true},
		{`"typeIds":[46,47,59,60],"commandStates":[1,2]`, true},
		{`"typeIds":[45,46],"commandQualifiers":[0]`, true},
		{`"typeIds":[46],"commandStates":[1,1]`, true}, // COT permits duplicate list values.
		{`"commandStates":[1]`, false}, {`"commandQualifiers":[0]`, false},
		{`"typeIds":[45,46],"commandStates":[1]`, false},
		{`"typeIds":[46],"commandStates":[0]`, false},
		{`"typeIds":[46],"commandStates":[3]`, false},
		{`"typeIds":[45],"commandStates":[-1]`, false},
		{`"typeIds":[45],"commandStates":[2]`, false},
		{`"typeIds":[46],"commandQualifiers":[-1]`, false},
		{`"typeIds":[46],"commandQualifiers":[32]`, false},
	} {
		t.Run(tc.fields, func(t *testing.T) {
			var p ICSPredicate
			err := json.Unmarshal([]byte(`{"protocol":"iec104",`+tc.fields+`}`), &p)
			if err == nil {
				err = ValidateICSPredicate(p, "test")
			}
			if (err == nil) != tc.valid {
				t.Fatalf("valid=%v error=%v", tc.valid, err)
			}
			if tc.valid {
				b, err := json.Marshal(p)
				if err != nil {
					t.Fatal(err)
				}
				var round ICSPredicate
				if err = json.Unmarshal(b, &round); err != nil {
					t.Fatal(err)
				}
				if !reflect.DeepEqual(p, round) {
					t.Fatalf("roundtrip changed predicate: %+v => %+v", p, round)
				}
				if p.Empty() {
					t.Fatal("nonempty predicate")
				}
			}
		})
	}
	for _, key := range []string{"commandStates", "commandQualifiers"} {
		for _, value := range []string{"null", "[]", "[null]", "[1.5]", "[\"1\"]", "true"} {
			var p ICSPredicate
			if err := json.Unmarshal([]byte(fmt.Sprintf(`{"protocol":"iec104","typeIds":[46],%q:%s}`, key, value)), &p); err == nil {
				t.Errorf("accepted %s=%s", key, value)
			}
		}
		for _, protocol := range []string{"modbus", "dnp3", "cip", ""} {
			var p ICSPredicate
			err := json.Unmarshal([]byte(fmt.Sprintf(`{"protocol":%q,%q:[1]}`, protocol, key)), &p)
			if err == nil {
				err = ValidateICSPredicate(p, "test")
			}
			if err == nil {
				t.Errorf("accepted %s on %q", key, protocol)
			}
		}
		for _, typeID := range []int{1, 48, 49, 50, 51, 61, 62, 63, 64, 100} {
			p := ICSPredicate{Protocol: "iec104", TypeIDs: []int{typeID}}
			if key == "commandStates" {
				p.CommandStates = []int{1}
			} else {
				p.CommandQualifiers = []int{0}
			}
			if ValidateICSPredicate(p, "test") == nil {
				t.Errorf("accepted %s type %d", key, typeID)
			}
		}
		p := ICSPredicate{Protocol: "iec104", TypeIDs: []int{46}}
		if key == "commandStates" {
			p.CommandStates = []int{}
		} else {
			p.CommandQualifiers = []int{}
		}
		if ValidateICSPredicate(p, "test") == nil {
			t.Errorf("accepted empty %s", key)
		}
	}
	for _, fields := range []string{`"commandState":[1]`, `"CommandStates":[1]`, `"commandStates":[1],"commandStates":[2]`} {
		var p ICSPredicate
		if json.Unmarshal([]byte(`{"protocol":"iec104","typeIds":[46],`+fields+`}`), &p) == nil {
			t.Errorf("accepted unknown/duplicate key %s", fields)
		}
	}
}
