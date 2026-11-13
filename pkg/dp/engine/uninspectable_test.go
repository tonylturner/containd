// SPDX-License-Identifier: Apache-2.0
package engine

import (
	"net"
	"strings"
	"testing"

	"github.com/tonylturner/containd/pkg/dp/capture"
	"github.com/tonylturner/containd/pkg/dp/coverage"
	"github.com/tonylturner/containd/pkg/dp/flow"
	"github.com/tonylturner/containd/pkg/dp/markabi"
	"github.com/tonylturner/containd/pkg/dp/rules"
)

func TestUninspectableDecisionFastPath(t *testing.T) {
	for _, tc := range []struct {
		name       string
		inspectAll bool
		protocols  map[string]bool
		exclusions []DPIExclusion
	}{
		{name: "default decoders"},
		{name: "enabled decoders", protocols: map[string]bool{"modbus": true, "dnp3": true, "iec104": true, "cip": true}},
		{name: "unrelated IP exclusion", exclusions: []DPIExclusion{{Type: "ip", Value: "192.0.2.1"}}},
		{name: "unrelated CIDR exclusion", exclusions: []DPIExclusion{{Type: "cidr", Value: "192.0.2.0/24"}}},
		{name: "domain exclusion", exclusions: []DPIExclusion{{Type: "domain", Value: "example.com"}}},
		{name: "inspect all", inspectAll: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			e := &Engine{
				dpiEnabled:    !tc.inspectAll,
				inspectAll:    tc.inspectAll,
				coverage:      coverage.Settings{ICSProtocols: tc.protocols},
				dpiExclusions: tc.exclusions,
			}
			// A nil evaluator makes any transport-scope rule walk fail.
			// Available inspection must bypass even eligible enforcing rules.
			e.ruleSnap.current.Store(&compiledRules{snapshot: &rules.Snapshot{
				DPIMode: "enforce",
				Firewall: []rules.Entry{clientToServer("guard", "502", rules.ActionAllow,
					rules.ICSPredicate{Protocol: "modbus", Mode: "enforce", ReadOnly: true})},
			}})
			state := &flow.State{Key: flow.Key{
				SrcIP: net.ParseIP(testClient), DstIP: net.ParseIP(testServer),
				SrcPort: 41000, DstPort: 502, Proto: 6,
			}}
			pkt := capture.Packet{Token: capture.NewToken(1, 1)}
			if got, decided := e.uninspectableDecision(pkt, state); decided {
				t.Fatalf("decision=%+v, decided=%v; want no decision", got, decided)
			}
		})
	}
}

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
