// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

package engine

import (
	"net"
	"testing"
	"time"

	"github.com/tonylturner/containd/pkg/dp/dpi"
	"github.com/tonylturner/containd/pkg/dp/flow"
	"github.com/tonylturner/containd/pkg/dp/rules"
)

func TestIEC104EventsNeverFeedInventoryOrLearner(t *testing.T) {
	e, err := New(Config{DPIEnabled: true})
	if err != nil {
		t.Fatal(err)
	}
	e.LoadRules(rules.Snapshot{Firewall: []rules.Entry{{ID: "monitor", ICS: rules.ICSPredicate{Protocol: "modbus", Mode: "monitor"}}}})
	state := flow.NewState(flow.Key{SrcIP: net.ParseIP("10.60.60.10"), DstIP: net.ParseIP("10.30.30.30"), SrcPort: 40000, DstPort: 2404, Proto: 6}, time.Now())
	cmd := dpi.Event{Proto: "iec104", Kind: "request", Attributes: map[string]any{
		"session_id": "run-1", "apdu_id": "run-1/c/0", "class": "control", "type_id": uint8(46),
		"ca": uint16(1), "ioa": uint32(2001), "select": false, "direction": "request", "is_write": true,
	}}
	e.RecordDPIEvents(state, &dpi.ParsedPacket{Proto: "tcp"}, []dpi.Event{cmd})
	if got := e.Inventory().List(); len(got) != 0 {
		t.Fatalf("inventory learned IEC104: %+v", got)
	}
	if got := e.Learner().Profiles(); len(got) != 0 {
		t.Fatalf("learner learned IEC104: %+v", got)
	}
	var alert map[string]any
	for _, ev := range e.Events().List(0) {
		if ev.Kind == "signature_match" && ev.Attributes["signature_id"] == "IEC104-CONTROL-CMD" {
			alert = ev.Attributes
		}
	}
	if alert == nil {
		t.Fatal("no IEC104 command signature alert")
	}
	for _, k := range []string{"session_id", "apdu_id", "type_id", "ca", "ioa", "select", "direction"} {
		if alert[k] != cmd.Attributes[k] {
			t.Fatalf("derived alert %s = %v, want %v", k, alert[k], cmd.Attributes[k])
		}
	}
	// Alerts derived from other protocols keep their existing shape.
	mb := dpi.Event{Proto: "modbus", Kind: "request", Attributes: map[string]any{"function_code": uint8(8), "unit_id": uint8(0), "sub_function": uint16(4), "is_write": true}}
	e.RecordDPIEvents(state, &dpi.ParsedPacket{Proto: "tcp"}, []dpi.Event{mb})
	for _, ev := range e.Events().List(0) {
		if ev.Kind == "signature_match" && ev.Attributes["signature_id"] == "MODBUS-FORCE-001" {
			if _, ok := ev.Attributes["function_code"]; ok || len(ev.Attributes) != 4 {
				t.Fatalf("modbus alert attributes changed: %v", ev.Attributes)
			}
		}
	}
}
