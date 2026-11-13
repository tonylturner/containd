// SPDX-License-Identifier: Apache-2.0
package engine

import (
	"strings"
	"testing"

	"github.com/tonylturner/containd/pkg/dp/capture"
	"github.com/tonylturner/containd/pkg/dp/markabi"
	"github.com/tonylturner/containd/pkg/dp/rules"
)

func TestUninspectableEnforceDrops(t *testing.T) {
	for _, tc := range []struct {
		proto, port string
		number      uint16
		action      rules.Action
		payload     []byte
	}{
		{"modbus", "502", 502, rules.ActionAllow, modbusADU(1, 6, 1, 0x1234)},
		{"dnp3", "20000", 20000, rules.ActionDeny, dnp3Operate(5, 9)},
		{"iec104", "2404", 2404, rules.ActionAllow, startdtAct},
	} {
		for _, cause := range []string{"master", "decoder", "ip", "cidr"} {
			t.Run(tc.proto+"/"+cause, func(t *testing.T) {
				cfg := Config{DPIEnabled: cause != "master", DPIMode: "enforce", NFQueueGroup: 101, Enforce: EnforceConfig{Enabled: true, ClearMark: noPolicyMarks}}
				if cause == "decoder" {
					cfg.DPIICSProtocols = map[string]bool{tc.proto: false}
				}
				if cause == "ip" {
					cfg.DPIExclusions = []DPIExclusion{{Type: "ip", Value: testServer}}
				}
				if cause == "cidr" {
					cfg.DPIExclusions = []DPIExclusion{{Type: "cidr", Value: "172.31.0.0/16"}}
				}
				e, err := New(cfg)
				if err != nil {
					t.Fatal(err)
				}
				pred := rules.ICSPredicate{Protocol: tc.proto, Mode: "enforce", ReadOnly: true}
				if tc.proto == "dnp3" {
					pred.ReadOnly = false
					pred.FunctionCode = []uint8{5}
				}
				entry := clientToServer("guard", tc.port, tc.action, pred)
				beforeApply := e.PreviewRule(PreviewRuleRequest{Entry: entry})
				causeText := map[string]string{"master": "DPI is off", "decoder": tc.proto + " decoder is off", "ip": "DPI exclusion " + testServer, "cidr": "DPI exclusion 172.31.0.0/16"}[cause]
				found := false
				for _, warning := range beforeApply.Warnings {
					found = found || strings.Contains(warning.Message, causeText)
				}
				if !found {
					t.Errorf("preview before apply lacks cause %q: %+v", causeText, beforeApply.Warnings)
				}
				e.LoadRules(rules.Snapshot{DPIMode: "enforce", Default: rules.ActionAllow, Firewall: []rules.Entry{entry}})
				syn := connSegment(false, 41000, tc.number, 100, capture.TCPFlagSYN, nil)
				syn.Token = capture.NewToken(1, 2)
				syn.Mark, syn.HasMark = markabi.EnforceScopeMark, true
				if got := e.HandlePacket(syn); got.Action != capture.Drop {
					t.Errorf("SYN decision=%+v, want drop", got)
				}
				pkt := connSegment(false, 41000, tc.number, 100, ackPsh, tc.payload)
				pkt.Token = capture.NewToken(1, 1)
				pkt.Mark, pkt.HasMark = markabi.EnforceScopeMark, true
				got := e.HandlePacket(pkt)
				if got.Action != capture.Drop || got.Reason != "ics_uninspectable_"+cause {
					t.Fatalf("decision=%+v, want named uninspectable drop", got)
				}
				reply := connSegment(true, 41000, tc.number, 500, ackPsh, nil)
				reply.Token, reply.Mark, reply.HasMark = capture.NewToken(1, 3), markabi.EnforceScopeMark, true
				if got := e.HandlePacket(reply); got.Action != capture.Drop || got.Reason != "ics_uninspectable_"+cause {
					t.Fatalf("reply decision=%+v, want the same scoped drop", got)
				}
				for _, ev := range e.Events().List(0) {
					if ev.Proto == tc.proto && (ev.Kind == "request" || ev.Kind == "response") {
						t.Fatalf("unexpected decoder event: %+v", ev)
					}
				}
				entry.ICS.Mode = "monitor"
				e.LoadRules(rules.Snapshot{DPIMode: "enforce", Default: rules.ActionAllow, Firewall: []rules.Entry{entry}})
				syn.Mark = 0
				if got := e.HandlePacket(syn); got.Action != capture.Repeat {
					t.Fatalf("monitor decision=%+v, want unchanged continuation", got)
				}
			})
		}
	}
}
