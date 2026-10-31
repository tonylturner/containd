// SPDX-License-Identifier: Apache-2.0
package engine

import (
	"fmt"
	"testing"

	"github.com/tonylturner/containd/pkg/dp/dpi"
	"github.com/tonylturner/containd/pkg/dp/ics/eventfields"
	"github.com/tonylturner/containd/pkg/dp/rules"
)

func TestDifferentDecodedProtocolRetainsEnforcingScope(t *testing.T) {
	for _, parsing := range []string{"tolerant", "strict"} {
		for _, reverse := range []bool{false, true} {
			for _, mode := range []string{"enforce", "monitor"} {
				t.Run(fmt.Sprintf("%s/reverse=%t/%s", parsing, reverse, mode), func(t *testing.T) {
					e, err := New(Config{DPIEnabled: true, DPIMode: "enforce", DPIICSParsing: map[string]string{"dnp3": parsing}})
					if err != nil {
						t.Fatal(err)
					}
					scopeID, monitorID := "a-scope", "z-monitor"
					if reverse {
						scopeID, monitorID = monitorID, scopeID
					}
					e.LoadRules(rules.Snapshot{Default: rules.ActionDeny, Firewall: []rules.Entry{
						{ID: monitorID, Action: rules.ActionAllow, ICS: rules.ICSPredicate{Protocol: "dnp3", Mode: "monitor"}},
						{ID: scopeID, Action: rules.ActionAllow, Protocols: []rules.Protocol{{Name: "tcp"}},
							ICS: rules.ICSPredicate{Protocol: "modbus", Mode: mode}},
					}})
					state := conformanceState()
					state.Key.DstPort = 20000
					pkt := &dpi.ParsedPacket{Proto: "tcp", SrcPort: state.Key.SrcPort, DstPort: state.Key.DstPort}
					ev := dpi.Event{Proto: "dnp3", Kind: "request", Attributes: map[string]any{
						"function_code": uint8(1), eventfields.KeyConformance: []string{"dnp3.test"},
					}}
					got, _, denied := e.enforceDPIEvents(state, pkt, []dpi.Event{ev}, false)
					if denied != (mode == "enforce") {
						t.Fatalf("decoded DNP3 escaped %s Modbus L3/L4 scope: %+v", mode, got)
					}
					if shadowHits(e, monitorID) != 1 {
						t.Fatal("enforce scope masked independent monitor match")
					}
					if mode == "enforce" && parsing == "strict" {
						if got.Reason != reasonNonconformant {
							t.Fatalf("strict finding did not preempt default: %+v", got)
						}
						decs := findingEvents(e, eventfields.KindDecision)
						found := false
						for _, d := range decs {
							if d.Attributes["reason"] == reasonNonconformant {
								found = true
								if d.Attributes["scopeId"] != scopeID || d.Attributes["ruleId"] != nil || d.Attributes["action"] != nil {
									t.Fatalf("lost original L3/L4 scope attribution: %+v", d)
								}
							}
						}
						if !found {
							t.Fatal("missing strict scope decision")
						}
					}
				})
			}
		}
	}
}
