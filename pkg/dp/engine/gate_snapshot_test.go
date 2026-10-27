// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 containd Authors

package engine

import (
	"context"
	"strings"
	"testing"

	"github.com/tonylturner/containd/pkg/dp/rules"
)

// ApplyRules refuses a snapshot whose gate selection covers an ICS decoder
// port before swapping, whatever compiled it.
func TestApplyRulesRejectsGateDecoderPort(t *testing.T) {
	e := newOrientationEngine(t)
	e.LoadRules(rules.Snapshot{Default: rules.ActionAllow})
	bad := rules.Snapshot{Default: rules.ActionDeny, Gate: rules.GateSelection{Enabled: true,
		Include: []rules.GateEntry{{DestZones: []string{"wan"}, Ports: []rules.GatePortRange{{Lo: 2000, Hi: 3000}}}},
		Zones:   []rules.GateZone{{Name: "wan", Index: 1, Devices: []string{"eth0"}}},
	}}
	err := e.ApplyRules(context.Background(), bad)
	if err == nil || !strings.Contains(err.Error(), "cip/2222") {
		t.Fatalf("ApplyRules = %v, want the decoder port named", err)
	}
	if got := e.CurrentRules().Default; got != rules.ActionAllow {
		t.Fatalf("rejected snapshot was swapped in: default %s", got)
	}
	bad.Gate.Include[0].Ports = []rules.GatePortRange{{Lo: 80, Hi: 80}}
	if err := e.ApplyRules(context.Background(), bad); err != nil {
		t.Fatalf("valid gate rejected: %v", err)
	}
	if got := e.CurrentRules().Gate.Zones[0].Index; got != 1 {
		t.Fatalf("gate not carried into the current snapshot: %+v", e.CurrentRules().Gate)
	}
}
