// SPDX-License-Identifier: Apache-2.0

package rules

import (
	"reflect"
	"testing"
)

func TestICSPredicateFieldCoverage(t *testing.T) {
	fields := map[string]struct {
		pred       ICSPredicate
		iecInvalid bool
	}{
		"Protocol":      {ICSPredicate{Protocol: ProtocolIEC104}, false},
		"FunctionCode":  {ICSPredicate{FunctionCode: []uint8{0}}, true},
		"UnitID":        {ICSPredicate{UnitID: u8(0)}, true},
		"Addresses":     {ICSPredicate{Addresses: []string{"0"}}, true},
		"ObjectClasses": {ICSPredicate{ObjectClasses: []uint16{0}}, true},
		"ReadOnly":      {ICSPredicate{ReadOnly: true}, false},
		"WriteOnly":     {ICSPredicate{WriteOnly: true}, true},
		"Direction":     {ICSPredicate{Direction: "request"}, false},
		"Mode":          {ICSPredicate{Mode: "enforce"}, false},
		"TypeIDs":       {ICSPredicate{TypeIDs: []int{1}}, false},
		"Classes":       {ICSPredicate{Classes: []string{"control"}}, false},
		"CA":            {ICSPredicate{CA: []uint16{0}}, false},
		"IOA":           {ICSPredicate{IOA: []IOARange{{Start: 0, End: 0}}}, false},
		"COT":           {ICSPredicate{COT: []int{1}}, false},
		"Originators":   {ICSPredicate{Originators: []int{0}}, false},
		"Negative":      {ICSPredicate{Negative: boolPtr(false)}, false},
		"Test":          {ICSPredicate{Test: boolPtr(false)}, false},
		"SelectExecute": {ICSPredicate{SelectExecute: "execute"}, false},
		"Masters":       {ICSPredicate{Masters: []uint16{0}}, true},
		"Outstations":   {ICSPredicate{Outstations: []uint16{0}}, true},
		"Groups":        {ICSPredicate{Groups: []int{0}}, true},
		"Variations":    {ICSPredicate{Variations: []int{0}}, true},
		"Instances":     {ICSPredicate{Instances: []uint16{0}}, true},
		"Attributes":    {ICSPredicate{Attributes: []uint16{0}}, true},
		"Tags":          {ICSPredicate{Tags: []string{"A"}}, true},
	}
	typ := reflect.TypeFor[ICSPredicate]()
	if typ.NumField() != len(fields) {
		t.Fatalf("predicate has %d fields, coverage enumerates %d; classify every new field", typ.NumField(), len(fields))
	}
	for i := range typ.NumField() {
		name := typ.Field(i).Name
		tc, ok := fields[name]
		if !ok {
			t.Fatalf("field %s not enumerated", name)
		}
		t.Run(name, func(t *testing.T) {
			if reflect.ValueOf(tc.pred).Field(i).IsZero() {
				t.Fatal("field coverage fixture does not populate its named field")
			}
			// Mode is explicitly operational metadata, never a packet predicate.
			if got, want := icsPredicateEmpty(tc.pred), name == "Mode"; got != want {
				t.Errorf("empty = %v, want %v", got, want)
			}
			if got := compileIEC104(tc.pred).invalid; got != tc.iecInvalid {
				t.Errorf("IEC invalid = %v, want %v", got, tc.iecInvalid)
			}
		})
	}
}

func TestICSSelectorConjunctions(t *testing.T) {
	for _, tc := range []struct {
		protocol string
		pred     ICSPredicate
		obj      ICSContext
		mutate   map[string]func(*ICSContext)
	}{
		{"dnp3", ICSPredicate{Masters: []uint16{7}, Outstations: []uint16{8}, Groups: []int{1},
			Variations: []int{2}, Addresses: []string{"10-20"}},
			ICSContext{Master: u16(7), Outstation: u16(8), Group: u8(1), Variation: u8(2), Spans: []AddressSpan{span(10, 20)}},
			map[string]func(*ICSContext){
				"master":     func(c *ICSContext) { c.Master = u16(8) },
				"outstation": func(c *ICSContext) { c.Outstation = u16(7) },
				"group":      func(c *ICSContext) { c.Group = u8(2) },
				"variation":  func(c *ICSContext) { c.Variation = u8(3) },
				"address":    func(c *ICSContext) { c.Spans = []AddressSpan{span(21, 21)} },
			}},
		{"cip", ICSPredicate{ObjectClasses: []uint16{1}, Instances: []uint16{2}, Attributes: []uint16{3}},
			ICSContext{HasObjectClass: true, ObjectClass: 1, Instance: u16(2), Attribute: u16(3)},
			map[string]func(*ICSContext){
				"class":     func(c *ICSContext) { c.ObjectClass = 4 },
				"instance":  func(c *ICSContext) { c.Instance = u16(4) },
				"attribute": func(c *ICSContext) { c.Attribute = u16(4) },
			}},
		{ProtocolIEC104, ICSPredicate{COT: []int{6}, Originators: []int{0}, Negative: boolPtr(false),
			Test: boolPtr(false), SelectExecute: "execute"},
			ICSContext{IEC104: &IEC104Context{COT: u8(6), Originator: u8(0), Negative: boolPtr(false),
				Test: boolPtr(false), Select: boolPtr(false)}},
			map[string]func(*ICSContext){
				"cot":        func(c *ICSContext) { c.IEC104.COT = u8(7) },
				"originator": func(c *ICSContext) { c.IEC104.Originator = u8(1) },
				"negative":   func(c *ICSContext) { c.IEC104.Negative = boolPtr(true) },
				"test":       func(c *ICSContext) { c.IEC104.Test = boolPtr(true) },
				"select":     func(c *ICSContext) { c.IEC104.Select = boolPtr(true) },
			}},
	} {
		for _, action := range []Action{ActionAllow, ActionDeny} {
			t.Run(tc.protocol+"/"+string(action), func(t *testing.T) {
				pred, obj := tc.pred, tc.obj
				pred.Protocol, obj.Protocol = tc.protocol, tc.protocol
				entry := Entry{Action: action, ICS: pred}
				if !PreviewMatch(entry, EvalContext{ICS: &obj}) {
					t.Fatal("positive conjunction did not match")
				}
				for name, mutate := range tc.mutate {
					changed := obj
					if obj.IEC104 != nil {
						copyIEC := *obj.IEC104
						changed.IEC104 = &copyIEC
					}
					mutate(&changed)
					if PreviewMatch(entry, EvalContext{ICS: &changed}) {
						t.Errorf("conjunction matched with changed %s", name)
					}
				}
			})
		}
	}
}
