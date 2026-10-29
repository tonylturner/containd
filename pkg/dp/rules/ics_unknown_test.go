// SPDX-License-Identifier: Apache-2.0

package rules

import "testing"

func TestICSObjectUnknown(t *testing.T) {
	selectors := map[string]ICSPredicate{
		"group":     {Protocol: "dnp3", Groups: []int{1}},
		"variation": {Protocol: "dnp3", Variations: []int{1}},
		"address":   {Protocol: "dnp3", Addresses: []string{"1"}},
		"dnp3 conjunction": {Protocol: "dnp3", Groups: []int{1}, Variations: []int{1},
			Addresses: []string{"1"}},
		"class":     {Protocol: "cip", ObjectClasses: []uint16{1}},
		"instance":  {Protocol: "cip", Instances: []uint16{1}},
		"attribute": {Protocol: "cip", Attributes: []uint16{1}},
		"tag":       {Protocol: "cip", Tags: []string{"A"}},
		"cip conjunction": {Protocol: "cip", ObjectClasses: []uint16{1},
			Instances: []uint16{1}, Attributes: []uint16{1}},
	}
	for name, pred := range selectors {
		for _, action := range []Action{ActionAllow, ActionDeny} {
			t.Run(name+"/"+string(action), func(t *testing.T) {
				// All known object fields contradict the predicate. ObjectUnknown
				// overrides the whole conjunction, not just the missing fields.
				obj := ICSContext{Protocol: pred.Protocol, ObjectUnknown: true,
					Group: u8(2), Variation: u8(2), Spans: []AddressSpan{span(2, 2)},
					ObjectClass: 2, HasObjectClass: true, Instance: u16(2), Attribute: u16(2), Symbol: []string{"B"}}
				entry := Entry{Action: action, ICS: pred}
				if got := PreviewMatch(entry, EvalContext{ICS: &obj}); got != (action == ActionDeny) {
					t.Fatalf("unknown object match = %v", got)
				}
				obj.ObjectUnknown = false
				if PreviewMatch(entry, EvalContext{ICS: &obj}) {
					t.Fatal("known mismatched object matched")
				}
			})
		}
	}
}

func TestICSCoverageRetainsMessageConstraints(t *testing.T) {
	for _, protocol := range []string{"dnp3", "cip"} {
		for _, action := range []Action{ActionAllow, ActionDeny} {
			t.Run(protocol+"/"+string(action), func(t *testing.T) {
				coverage := ICSContext{Protocol: protocol, Direction: "request", Master: u16(7),
					Outstation: u16(8), ObjectUnknown: true}
				broad := Entry{Action: action, ICS: ICSPredicate{Protocol: protocol, Direction: "request"}}
				if !PreviewMatch(broad, EvalContext{ICS: &coverage}) {
					t.Fatal("object-unconstrained rule must cover incomplete inspection")
				}
				for name, pred := range map[string]ICSPredicate{
					"function": {Protocol: protocol, FunctionCode: []uint8{0}},
					"read":     {Protocol: protocol, ReadOnly: true},
					"write":    {Protocol: protocol, WriteOnly: true},
				} {
					if PreviewMatch(Entry{Action: action, ICS: pred}, EvalContext{ICS: &coverage}) {
						t.Errorf("coverage matched %s constraint without evidence", name)
					}
				}
				pred := ICSPredicate{Protocol: protocol, FunctionCode: []uint8{0}, ReadOnly: true, Direction: "request"}
				if protocol == "dnp3" {
					pred.Groups, pred.Masters, pred.Outstations = []int{1}, []uint16{7}, []uint16{8}
				} else {
					pred.Tags = []string{"A"}
				}
				known := coverage
				known.HasFunctionCode, known.ReadOnly = true, true
				ctx := EvalContext{Proto: "tcp", Port: "20000", SrcZone: "lan", ICS: &known}
				entry := Entry{Action: action, ICS: pred, SourceZones: []string{"lan"},
					Protocols: []Protocol{{Name: "tcp", Port: "20000"}}}
				if got := PreviewMatch(entry, ctx); got != (action == ActionDeny) {
					t.Fatalf("known message with unknown object match = %v", got)
				}
				mutations := map[string]func(*EvalContext){
					"function missing": func(c *EvalContext) { c.ICS.HasFunctionCode = false },
					"function changed": func(c *EvalContext) { c.ICS.FunctionCode = 1 },
					"access":           func(c *EvalContext) { c.ICS.ReadOnly = false },
					"direction":        func(c *EvalContext) { c.ICS.Direction = "response" },
					"zone":             func(c *EvalContext) { c.SrcZone = "wan" },
					"port":             func(c *EvalContext) { c.Port = "1" },
					"protocol":         func(c *EvalContext) { c.ICS.Protocol = "modbus" },
				}
				if protocol == "dnp3" {
					mutations["station swapped"] = func(c *EvalContext) { c.ICS.Master, c.ICS.Outstation = u16(8), u16(7) }
					mutations["station absent"] = func(c *EvalContext) { c.ICS.Master = nil }
				}
				for name, mutate := range mutations {
					copyObj, copyCtx := known, ctx
					copyCtx.ICS = &copyObj
					mutate(&copyCtx)
					if PreviewMatch(entry, copyCtx) {
						t.Errorf("ObjectUnknown bypassed %s", name)
					}
				}
			})
		}
	}
}

func TestICSSelectorUnknownFlags(t *testing.T) {
	for _, tc := range []struct {
		name string
		pred ICSPredicate
		obj  ICSContext
	}{
		{"point", ICSPredicate{Protocol: "dnp3", Groups: []int{1}, Addresses: []string{"1"}},
			ICSContext{Protocol: "dnp3", Group: u8(1), SpansUnknown: true, Spans: []AddressSpan{span(1, 1)}}},
		{"instance", ICSPredicate{Protocol: "cip", ObjectClasses: []uint16{1}, Instances: []uint16{1}},
			ICSContext{Protocol: "cip", ObjectClass: 1, HasObjectClass: true, InstanceUnknown: true, Instance: u16(1)}},
		{"attribute", ICSPredicate{Protocol: "cip", ObjectClasses: []uint16{1}, Attributes: []uint16{1}},
			ICSContext{Protocol: "cip", ObjectClass: 1, HasObjectClass: true, AttributeUnknown: true, Attribute: u16(1)}},
	} {
		for _, action := range []Action{ActionAllow, ActionDeny} {
			t.Run(tc.name+"/"+string(action), func(t *testing.T) {
				entry := Entry{Action: action, ICS: tc.pred}
				obj := tc.obj
				if got := PreviewMatch(entry, EvalContext{ICS: &obj}); got != (action == ActionDeny) {
					t.Fatalf("selector unknown match = %v", got)
				}
				// A per-selector unknown flag must not override a different selector.
				obj.Group, obj.ObjectClass = u8(2), 2
				if PreviewMatch(entry, EvalContext{ICS: &obj}) {
					t.Fatal("selector unknown bypassed other object selector")
				}
				// Without its selector, a flag imposes no restriction.
				pred := ICSPredicate{Protocol: tc.pred.Protocol}
				if !PreviewMatch(Entry{Action: action, ICS: pred}, EvalContext{ICS: &obj}) {
					t.Fatal("unconstrained unknown selector must match")
				}
			})
		}
	}
}
