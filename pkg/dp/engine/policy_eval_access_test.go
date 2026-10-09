// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

package engine

import (
	"net"
	"testing"
	"time"

	"github.com/tonylturner/containd/pkg/dp/dpi"
	"github.com/tonylturner/containd/pkg/dp/flow"
)

func TestEvalContextReadWriteNeedsPresentIsWrite(t *testing.T) {
	state := flow.NewState(flow.Key{SrcIP: net.ParseIP("10.0.0.1"), DstIP: net.ParseIP("10.0.0.2"), SrcPort: 40000, DstPort: 502, Proto: 6}, time.Now())
	pkt := &dpi.ParsedPacket{Proto: "tcp", SrcPort: 40000, DstPort: 502}
	cases := []struct {
		attrs        map[string]any
		read, write  bool
		fc           uint8
		unitID       *uint8
		describeCase string
	}{
		{map[string]any{"is_write": false, "function_code": uint8(3)}, true, false, 3, nil, "decoded read"},
		{map[string]any{"is_write": true, "function_code": float64(6), "unit_id": float64(1)}, false, true, 6, ptr8(1), "JSON write"},
		{map[string]any{"function_code": uint8(3)}, false, false, 3, nil, "no is_write"},
		{map[string]any{"is_write": "false", "function_code": 2.5}, false, false, 0, nil, "wrong kinds and fraction"},
	}
	for _, c := range cases {
		ctx, ok := evalContextFromDPIEvent(nil, state, pkt, dpi.Event{Proto: "modbus", Kind: "request", Attributes: c.attrs}, "", "")
		if !ok {
			t.Fatalf("%s: no context", c.describeCase)
		}
		ics := ctx.ICS
		if ics.ReadOnly != c.read || ics.WriteOnly != c.write || ics.FunctionCode != c.fc {
			t.Fatalf("%s: read=%v write=%v fc=%d", c.describeCase, ics.ReadOnly, ics.WriteOnly, ics.FunctionCode)
		}
		if (ics.UnitID == nil) != (c.unitID == nil) || (ics.UnitID != nil && *ics.UnitID != *c.unitID) {
			t.Fatalf("%s: unit = %v", c.describeCase, ics.UnitID)
		}
	}
}

func ptr8(v uint8) *uint8 { return &v }
