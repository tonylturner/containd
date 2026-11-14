// SPDX-License-Identifier: Apache-2.0
package engine

import (
	"os"
	"testing"
	"time"

	"github.com/tonylturner/containd/pkg/common/telemetry"
	"github.com/tonylturner/containd/pkg/dp/events"
	"github.com/tonylturner/containd/pkg/dp/internal/corpus"
	"github.com/tonylturner/containd/pkg/dp/rules"
)

func TestDetachedUnsupportedPairingDecisions(t *testing.T) {
	const path = "../../../test/modbus/testdata/diagnostics.pcap"
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	records, _, err := corpus.ReadPCAP(f, path, corpus.ReadOptions{IgnoreEtherTypes: []uint16{0x0806}})
	if err != nil {
		t.Fatal(err)
	}
	for _, action := range []rules.Action{rules.ActionAllow, rules.ActionDeny} {
		for _, direction := range []string{"", "request"} {
			t.Run(string(action)+"/direction="+direction, func(t *testing.T) {
				store := events.NewStore(4096)
				d := mustDetached(t, store)
				d.LoadRules(rules.Snapshot{Default: rules.ActionDeny, Firewall: []rules.Entry{{
					ID: "diagnostics", Action: action,
					ICS: rules.ICSPredicate{Protocol: "modbus", Mode: "enforce", Direction: direction, FunctionCode: []uint8{8}},
				}}})
				for i, record := range records {
					pkt := record.Decoded
					pkt.Timestamp = time.Now().Add(time.Duration(i) * time.Millisecond)
					d.HandlePacket(pkt)
				}
				requests, decisions := 0, 0
				for _, ev := range store.ListTelemetry(0) {
					if ev.Kind == "ics.decision" && ev.Attributes["mode"] != "monitor" {
						t.Fatalf("decode-only replay reported enforcement: %+v", ev)
					}
					if ev.Kind == "request" && ev.Proto == "modbus" {
						requests++
						if ev.Attributes["pairing_reason"] != string(pairUnsupported) {
							t.Fatalf("diagnostics acquired pairing support: %+v", ev)
						}
					}
					if ev.Kind == "ics.decision" && ev.Attributes["ruleId"] == "diagnostics" {
						decisions++
						want := decisionWouldDrop
						if action == rules.ActionAllow {
							want = decisionWouldAllow
						}
						if ev.Origin != telemetry.OriginDemo || ev.Attributes["decision"] != want || ev.Attributes["mode"] != "monitor" {
							t.Fatalf("wrong observational decision: %+v", ev)
						}
					}
				}
				wantDecisions := 64
				if direction == "request" {
					wantDecisions = 32
				}
				if requests != 32 || decisions != wantDecisions {
					t.Fatalf("decoded %d diagnostics requests but emitted %d would-decisions", requests, decisions)
				}
				if d.engine.sessions.pairingTotal != 0 || len(d.engine.sessions.held) != 0 {
					t.Fatal("decode-only diagnostics acquired grants or held tokens")
				}
			})
		}
	}
}
