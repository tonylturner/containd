// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

package compile

import (
	"reflect"
	"testing"

	"github.com/tonylturner/containd/pkg/cp/config"
	"github.com/tonylturner/containd/pkg/dp/rules"
)

func TestICSPredicateCopiesFields(t *testing.T) {
	unitID := uint8(7)
	in := config.ICSPredicate{
		Protocol:      "iec104",
		FunctionCode:  []uint8{3},
		UnitID:        &unitID,
		Addresses:     []string{"0-10"},
		ObjectClasses: []uint16{2},
		ReadOnly:      true,
		WriteOnly:     true,
		Direction:     "request",
		Mode:          "enforce",
		TypeIDs:       []int{45, 46},
		Classes:       []string{"control"},
		CA:            []uint16{1},
		IOA:           []config.IOARange{{Start: 65536, End: 65567}},
		COT:           []int{6},
		Originators:   []int{0},
		Negative:      compileBoolPtr(false),
		Test:          compileBoolPtr(false),
		SelectExecute: "execute",
		Masters:       []uint16{0},
		Outstations:   []uint16{65519},
		Groups:        []int{0},
		Variations:    []int{0},
		Instances:     []uint16{0},
		Attributes:    []uint16{65535},
		Tags:          []string{"Program:Main.Pump"},
	}
	wantUnitID := uint8(7)
	want := rules.ICSPredicate{
		Protocol:      "iec104",
		FunctionCode:  []uint8{3},
		UnitID:        &wantUnitID,
		Addresses:     []string{"0-10"},
		ObjectClasses: []uint16{2},
		ReadOnly:      true,
		WriteOnly:     true,
		Direction:     "request",
		Mode:          "enforce",
		TypeIDs:       []int{45, 46},
		Classes:       []string{"control"},
		CA:            []uint16{1},
		IOA:           []rules.IOARange{{Start: 65536, End: 65567}},
		COT:           []int{6},
		Originators:   []int{0},
		Negative:      compileBoolPtr(false),
		Test:          compileBoolPtr(false),
		SelectExecute: "execute",
		Masters:       []uint16{0},
		Outstations:   []uint16{65519},
		Groups:        []int{0},
		Variations:    []int{0},
		Instances:     []uint16{0},
		Attributes:    []uint16{65535},
		Tags:          []string{"Program:Main.Pump"},
	}
	// Keep the complete explicit fixture above in lockstep with both types.
	// No zero fields: even pointer-false and list-zero values must survive.
	for _, typ := range []reflect.Type{reflect.TypeOf(in), reflect.TypeOf(want)} {
		if typ.NumField() != 25 {
			t.Fatalf("%s has %d fields; enumerate every predicate field in the copy fixture", typ, typ.NumField())
		}
	}
	for i := range reflect.TypeOf(in).NumField() {
		if reflect.ValueOf(in).Field(i).IsZero() {
			t.Fatalf("copy fixture omits %s", reflect.TypeOf(in).Field(i).Name)
		}
	}
	got := ICSPredicate(in)
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("ICSPredicate = %+v, want %+v", got, want)
	}

	// The DP predicate owns its memory.
	in.TypeIDs[0], in.Classes[0], in.CA[0], in.IOA[0].Start, in.FunctionCode[0] = 1, "monitor", 2, 3, 4
	in.Addresses[0], in.ObjectClasses[0] = "99", 5
	*in.UnitID = 9
	in.COT[0], in.Originators[0] = 7, 1
	*in.Negative, *in.Test = true, true
	in.Masters[0], in.Outstations[0], in.Groups[0], in.Variations[0] = 1, 2, 3, 4
	in.Instances[0], in.Attributes[0], in.Tags[0] = 5, 6, "Changed"
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("ICSPredicate shares memory with its input: %+v", got)
	}

	if zero := ICSPredicate(config.ICSPredicate{}); !reflect.DeepEqual(zero, rules.ICSPredicate{}) {
		t.Fatalf("empty predicate = %+v, want zero", zero)
	}
}

func compileBoolPtr(v bool) *bool { return &v }

func TestCompileSnapshotUsesICSPredicate(t *testing.T) {
	cfg := &config.Config{
		System:    config.SystemConfig{Hostname: "containd"},
		Zones:     []config.Zone{{Name: "scada"}},
		DataPlane: config.DataPlaneConfig{DPIEnabled: true, NFQueueGroup: 101},
		Firewall: config.FirewallConfig{
			DefaultAction: config.ActionDeny,
			Rules: []config.Rule{{
				ID:          "iec-cmd",
				SourceZones: []string{"scada"},
				Protocols:   []config.Protocol{{Name: "tcp", Port: "2404"}},
				ICS: config.ICSPredicate{
					Protocol: "iec104",
					TypeIDs:  []int{46},
					Classes:  []string{"control"},
					CA:       []uint16{1},
					IOA:      []config.IOARange{{Start: 65536, End: 65567}},
					Mode:     "enforce",
				},
				Action: config.ActionAllow,
			}},
		},
	}
	snap, err := CompileSnapshot(cfg)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	if got, want := snap.Firewall[0].ICS, ICSPredicate(cfg.Firewall.Rules[0].ICS); !reflect.DeepEqual(got, want) {
		t.Fatalf("compiled ICS = %+v, want %+v", got, want)
	}
}

// Direction and objectClasses used to be dropped by the
// compiler, so a direction-scoped rule matched both directions and a CIP
// object-class rule matched every class. They are now compiled and enforced.
func TestCompileSnapshotEnforcesDirectionAndObjectClasses(t *testing.T) {
	cfg := &config.Config{
		System: config.SystemConfig{Hostname: "containd"},
		Firewall: config.FirewallConfig{
			DefaultAction: config.ActionAllow,
			Rules: []config.Rule{
				{
					ID:     "deny-modbus-requests",
					ICS:    config.ICSPredicate{Protocol: "modbus", Direction: "request"},
					Action: config.ActionDeny,
				},
				{
					ID:     "deny-cip-identity",
					ICS:    config.ICSPredicate{Protocol: "cip", ObjectClasses: []uint16{0x01}},
					Action: config.ActionDeny,
				},
			},
		},
	}
	snap, err := CompileSnapshot(cfg)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	if got := snap.Firewall[0].ICS.Direction; got != "request" {
		t.Fatalf("compiled direction = %q, want request", got)
	}
	if got := snap.Firewall[1].ICS.ObjectClasses; !reflect.DeepEqual(got, []uint16{0x01}) {
		t.Fatalf("compiled objectClasses = %v, want [1]", got)
	}

	ev := rules.NewEvaluator(&snap)
	cases := []struct {
		name string
		ics  rules.ICSContext
		want rules.Action
	}{
		{"modbus request denied", rules.ICSContext{Protocol: "modbus", Direction: "request"}, rules.ActionDeny},
		{"modbus response passes", rules.ICSContext{Protocol: "modbus", Direction: "response"}, rules.ActionAllow},
		{"cip identity class denied", rules.ICSContext{Protocol: "cip", ObjectClass: 0x01, HasObjectClass: true}, rules.ActionDeny},
		{"cip other class passes", rules.ICSContext{Protocol: "cip", ObjectClass: 0x02, HasObjectClass: true}, rules.ActionAllow},
	}
	for _, tc := range cases {
		ics := tc.ics
		if got := ev.Evaluate(rules.EvalContext{Proto: "tcp", ICS: &ics}); got != tc.want {
			t.Errorf("%s: action = %s, want %s", tc.name, got, tc.want)
		}
	}
}
