// SPDX-License-Identifier: Apache-2.0

package engine

import (
	"fmt"
	"testing"

	"github.com/tonylturner/containd/pkg/dp/capture"
	"github.com/tonylturner/containd/pkg/dp/rules"
)

func TestHandlePacketCompetingICSPorts(t *testing.T) {
	for _, tc := range []struct {
		client, server uint16
		iec            bool
		protocol       string
		passive        bool
	}{
		{502, 2404, true, "iec104", false},
		{502, 2404, false, "modbus", true},
		{2404, 502, false, "modbus", true},
		{41000, 502, false, "modbus", false},
	} {
		t.Run(fmt.Sprintf("%d-%d/%s", tc.client, tc.server, tc.protocol), func(t *testing.T) {
			e := newObservationEngine(t)
			e.LoadRules(rules.Snapshot{Default: rules.ActionAllow, Firewall: []rules.Entry{
				{ICS: rules.ICSPredicate{Protocol: "iec104", Mode: "monitor"}, Action: rules.ActionAllow},
				{ICS: rules.ICSPredicate{Protocol: "modbus", Mode: "monitor"}, Action: rules.ActionAllow},
			}})
			trace := observationTrace(tc.server, tc.iec)
			// STARTDT activation/confirmation alone suffices for two IEC frames.
			trace = trace[:4]
			for i := range trace {
				if i%2 == 0 {
					trace[i].SrcPort = tc.client
				} else {
					trace[i].DstPort = tc.client
				}
				if d := e.HandlePacket(trace[i]); d.Action != capture.Accept {
					t.Fatalf("packet %d: %+v", i, d)
				}
			}
			decoded := 0
			for _, ev := range e.Events().List(0) {
				if ev.Proto != tc.protocol || ev.Kind == "ics.decision" {
					continue
				}
				if ev.Kind == "malformed" {
					t.Fatalf("selected protocol lost a direction: %+v", ev)
				}
				if (ev.Attributes["observation_only"] == true) != tc.passive {
					t.Fatalf("incorrect ownership: %+v", ev)
				}
				decoded++
			}
			if decoded != 2 {
				t.Fatalf("decoded=%d want 2: %+v", decoded, e.Events().List(0))
			}
		})
	}
}
