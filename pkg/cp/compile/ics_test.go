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
		Protocol:     "iec104",
		FunctionCode: []uint8{3},
		UnitID:       &unitID,
		Addresses:    []string{"0-10"},
		ReadOnly:     true,
		Mode:         "enforce",
		TypeIDs:      []int{45, 46},
		Classes:      []string{"control"},
		CA:           []uint16{1},
		IOA:          []config.IOARange{{Start: 65536, End: 65567}},
	}
	wantUnitID := uint8(7)
	want := rules.ICSPredicate{
		Protocol:     "iec104",
		FunctionCode: []uint8{3},
		UnitID:       &wantUnitID,
		Addresses:    []string{"0-10"},
		ReadOnly:     true,
		Mode:         "enforce",
		TypeIDs:      []int{45, 46},
		Classes:      []string{"control"},
		CA:           []uint16{1},
		IOA:          []rules.IOARange{{Start: 65536, End: 65567}},
	}
	got := ICSPredicate(in)
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("ICSPredicate = %+v, want %+v", got, want)
	}

	// The DP predicate owns its memory.
	in.TypeIDs[0], in.Classes[0], in.CA[0], in.IOA[0].Start, in.FunctionCode[0] = 1, "monitor", 2, 3, 4
	in.Addresses[0] = "99"
	*in.UnitID = 9
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("ICSPredicate shares memory with its input: %+v", got)
	}

	if zero := ICSPredicate(config.ICSPredicate{}); !reflect.DeepEqual(zero, rules.ICSPredicate{}) {
		t.Fatalf("empty predicate = %+v, want zero", zero)
	}
}

func TestCompileSnapshotUsesICSPredicate(t *testing.T) {
	cfg := &config.Config{
		System: config.SystemConfig{Hostname: "containd"},
		Zones:  []config.Zone{{Name: "scada"}},
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
