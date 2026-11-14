// SPDX-License-Identifier: Apache-2.0

package config

import (
	"encoding/json"
	"fmt"
	"reflect"
	"strings"
	"testing"
)

func TestPairingClassSchema(t *testing.T) {
	t.Run("roundtripClonePatch", func(t *testing.T) {
		for _, protocol := range []string{"dnp3", "iec104"} {
			for _, class := range []string{"autonomous", "session"} {
				p := ICSPredicate{Protocol: protocol, Direction: "response", MessageClass: class}
				if err := ValidateICSPredicate(p, "class"); err != nil {
					t.Fatal(err)
				}
				raw, err := json.Marshal(p)
				if err != nil {
					t.Fatal(err)
				}
				var copy ICSPredicate
				if err := json.Unmarshal(raw, &copy); err != nil || !reflect.DeepEqual(copy, p) {
					t.Fatalf("roundtrip %s: %+v %v", raw, copy, err)
				}
				clone := cloneDesiredValue(reflect.ValueOf(p)).Interface().(ICSPredicate)
				if !reflect.DeepEqual(clone, p) || clone.Empty() {
					t.Fatalf("clone lost selector: %+v", clone)
				}
				cleared, err := PatchICSPredicate(p, []byte(`{"messageClass":null}`))
				if err != nil || cleared.MessageClass != "" || cleared.Protocol != protocol {
					t.Fatalf("clear: %+v %v", cleared, err)
				}
				restored, err := PatchICSPredicate(cleared, []byte(fmt.Sprintf(`{"messageClass":%q}`, class)))
				if err != nil || !reflect.DeepEqual(restored, p) {
					t.Fatalf("restore: %+v %v", restored, err)
				}
				replaced, err := PatchICSPredicate(p, []byte(`{"protocol":"modbus"}`))
				if err != nil || !reflect.DeepEqual(replaced, ICSPredicate{Protocol: "modbus"}) {
					t.Fatalf("replacement: %+v %v", replaced, err)
				}
			}
		}
		if (ICSPredicate{MessageClass: "session"}).Empty() {
			t.Fatal("class alone is not empty")
		}
		raw, err := json.Marshal(ICSPredicate{Protocol: "dnp3"})
		if err != nil || strings.Contains(string(raw), "messageClass") {
			t.Fatalf("legacy predicate changed: %s %v", raw, err)
		}
	})
	t.Run("strictJSON", func(t *testing.T) {
		for _, value := range []string{`null`, `""`, `"unknown"`, `"request"`, `"solicited"`, `"Autonomous"`, `" session"`, `1`, `false`, `[]`, `{}`} {
			body := `{"protocol":"dnp3","direction":"response","messageClass":` + value + `}`
			var p ICSPredicate
			if err := json.Unmarshal([]byte(body), &p); err == nil {
				t.Errorf("accepted %s", body)
			}
			if value != "null" {
				if err := ValidateICSPredicatePatch([]byte(`{"messageClass":` + value + `}`)); err == nil {
					t.Errorf("patch accepted %s", value)
				}
			}
		}
		for _, body := range []string{
			`{"messageClass":"session"}`,
			`{"protocol":"dnp3","messageClass":"session"}`,
			`{"protocol":"dnp3","direction":"response","messageClass":"session","messageClass":"session"}`,
			`{"protocol":"dnp3","direction":"response","MessageClass":"session"}`,
			`{"protocol":"iec104","direction":"response","messageClass":"session","ca":[0]}`,
			`{"protocol":"dnp3","direction":"response","messageClass":"session","groups":[]}`,
			`{"protocol":"dnp3","direction":"response","messageClass":"session","writeOnly":false}`,
		} {
			var p ICSPredicate
			if err := json.Unmarshal([]byte(body), &p); err == nil {
				t.Errorf("accepted %s", body)
			}
		}
		if err := ValidateICSPredicatePatch([]byte(`{"messageClass":"session"}`)); err != nil {
			t.Fatal("partial patch must not require protocol/direction:", err)
		}
	})
	t.Run("compatibleSelectors", func(t *testing.T) {
		for _, p := range []ICSPredicate{
			{Protocol: "dnp3", Direction: "response", MessageClass: "autonomous"},
			{Protocol: "dnp3", Direction: "response", MessageClass: "autonomous", FunctionCode: []uint8{130}, Masters: []uint16{1}, Outstations: []uint16{2}, Groups: []int{1}, Variations: []int{2}, Addresses: []string{"0-3"}, ReadOnly: true},
			{Protocol: "dnp3", Direction: "request", MessageClass: "session", FunctionCode: []uint8{0}},
			{Protocol: "dnp3", Direction: "response", MessageClass: "session", Masters: []uint16{1}},
			{Protocol: "iec104", Direction: "request", MessageClass: "session", ReadOnly: true},
			{Protocol: "iec104", Direction: "response", MessageClass: "session"},
			{Protocol: "iec104", Direction: "response", MessageClass: "autonomous"},
			{Protocol: "iec104", Direction: "response", MessageClass: "autonomous", TypeIDs: []int{1, 30}, COT: []int{1, 2, 3}, CA: []uint16{1}, IOA: []IOARange{{Start: 1, End: 10}}, Classes: []string{"monitor"}, ReadOnly: true},
			{Protocol: "iec104", Direction: "response", MessageClass: "autonomous", TypeIDs: []int{70}, COT: []int{4}, Classes: []string{"system"}},
			{Protocol: "iec104", Direction: "response", MessageClass: "autonomous", TypeIDs: []int{1, 70}, COT: []int{3, 4}, Classes: []string{"monitor", "system"}},
		} {
			if err := ValidateICSPredicate(p, "valid"); err != nil {
				t.Errorf("%+v: %v", p, err)
			}
		}
	})
	t.Run("incompatibleSelectors", func(t *testing.T) {
		bases := []ICSPredicate{
			{Protocol: "dnp3", Direction: "response", MessageClass: "autonomous"},
			{Protocol: "iec104", Direction: "response", MessageClass: "autonomous"},
			{Protocol: "dnp3", Direction: "request", MessageClass: "session"},
			{Protocol: "iec104", Direction: "request", MessageClass: "session"},
		}
		for _, base := range bases {
			mutations := []func(*ICSPredicate){
				func(p *ICSPredicate) { p.Protocol = "" },
				func(p *ICSPredicate) { p.Protocol = "modbus" },
				func(p *ICSPredicate) { p.Protocol = "cip" },
				func(p *ICSPredicate) { p.Direction = "" },
				func(p *ICSPredicate) { p.Direction = "both" },
				func(p *ICSPredicate) { p.MessageClass = "unknown" },
				func(p *ICSPredicate) { p.WriteOnly = true },
				func(p *ICSPredicate) { p.ObjectClasses = []uint16{1} },
				func(p *ICSPredicate) { p.UnitID = new(uint8(1)) },
			}
			if base.MessageClass == "autonomous" {
				mutations = append(mutations, func(p *ICSPredicate) { p.Direction = "request" })
			} else {
				mutations = append(mutations,
					func(p *ICSPredicate) { p.Groups = []int{1} },
					func(p *ICSPredicate) { p.CA = []uint16{0} },
					func(p *ICSPredicate) { p.TypeIDs = []int{1} },
					func(p *ICSPredicate) { p.COT = []int{3} })
			}
			if base.Protocol == "dnp3" {
				mutations = append(mutations, func(p *ICSPredicate) { p.FunctionCode = []uint8{129} })
			} else if base.MessageClass == "autonomous" {
				mutations = append(mutations,
					func(p *ICSPredicate) { p.TypeIDs = []int{45} },
					func(p *ICSPredicate) { p.TypeIDs = []int{100} },
					func(p *ICSPredicate) { p.COT = []int{7} },
					func(p *ICSPredicate) { p.COT = []int{10} },
					func(p *ICSPredicate) { p.COT = []int{20} },
					func(p *ICSPredicate) { p.TypeIDs, p.COT = []int{70}, []int{3} },
					func(p *ICSPredicate) { p.TypeIDs, p.COT = []int{1}, []int{4} },
					func(p *ICSPredicate) { p.Classes = []string{"control"} },
					func(p *ICSPredicate) { p.Classes, p.TypeIDs = []string{"system"}, []int{1} },
					func(p *ICSPredicate) { p.Negative = new(true) },
					func(p *ICSPredicate) { p.SelectExecute = "execute" })
			}
			for i, mutate := range mutations {
				p := base
				mutate(&p)
				if err := ValidateICSPredicate(p, "invalid"); err == nil {
					t.Errorf("%s/%s mutation %d accepted: %+v", base.Protocol, base.MessageClass, i, p)
				}
			}
		}
	})
	t.Run("patchMergedValidation", func(t *testing.T) {
		p := ICSPredicate{Protocol: "dnp3", Direction: "response", FunctionCode: []uint8{129}}
		if _, err := PatchICSPredicate(p, []byte(`{"messageClass":"autonomous"}`)); err == nil {
			t.Fatal("incompatible inherited functionCode accepted")
		}
		got, err := PatchICSPredicate(p, []byte(`{"messageClass":"autonomous","functionCode":null}`))
		if err != nil || got.MessageClass != "autonomous" || got.FunctionCode != nil {
			t.Fatalf("repair by deleting inherited selector: %+v %v", got, err)
		}
		if _, err := PatchICSPredicate(got, []byte(`{"direction":null}`)); err == nil {
			t.Fatal("class survived removal of required direction")
		}
	})
}
