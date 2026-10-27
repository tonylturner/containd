// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 containd Authors

package engine

import (
	"testing"

	"github.com/tonylturner/containd/pkg/dp/capture"
	"github.com/tonylturner/containd/pkg/dp/dpi"
	"github.com/tonylturner/containd/pkg/dp/flow"
	"github.com/tonylturner/containd/pkg/dp/rules"
)

func TestModbusSource502ThroughConsumers(t *testing.T) {
	for _, port := range []uint16{41000, 502} {
		e := newModbusInspectEngine(t)
		requestRule := rules.Entry{ID: "requests", Action: rules.ActionAllow, Log: true,
			Protocols: []rules.Protocol{{Name: "tcp"}},
			ICS:       rules.ICSPredicate{Protocol: "modbus", Direction: "request", Addresses: []string{"10-11"}}}
		responseRule := rules.Entry{ID: "responses", Action: rules.ActionAllow, Log: true,
			Protocols: []rules.Protocol{{Name: "tcp"}},
			ICS:       rules.ICSPredicate{Protocol: "modbus", Direction: "response"}}
		e.LoadRules(rules.Snapshot{Default: rules.ActionDeny, Firewall: []rules.Entry{requestRule, responseRule}})
		packets := []capture.Packet{
			connSegment(false, 502, port, 100, capture.TCPFlagSYN, nil),
			connSegment(true, 502, port, 500, capture.TCPFlagSYN|capture.TCPFlagACK, nil),
			connSegment(false, 502, port, 100, ackPsh, modbusADU(1, 3, 10, 2)),
			connSegment(true, 502, port, 500, ackPsh, []byte{0, 1, 0, 0, 0, 7, 1, 3, 4, 0, 10, 0, 11}),
			connSegment(true, 502, port, 513, ackPsh, []byte{0, 2, 0, 0, 0, 3, 1, 0x83, 2}),
		}
		for _, p := range packets {
			e.handlePacket(p)
		}
		evs := modbusEventsOldestFirst(e)
		kinds := []string{"request", "response", "exception"}
		if len(evs) != 3 {
			t.Fatalf("server port %d events=%+v", port, evs)
		}
		for i, ev := range evs {
			if ev.Kind != kinds[i] {
				t.Fatalf("event %d=%+v", i, ev)
			}
		}
		if evs[0].Attributes["address"] != uint16(10) || evs[0].Attributes["quantity"] != uint16(2) {
			t.Fatalf("request fields=%+v", evs[0])
		}
		if ruleHits(e, "requests") != 1 || ruleHits(e, "responses") != 2 {
			t.Fatalf("policy direction counts request=%d response=%d", ruleHits(e, "requests"), ruleHits(e, "responses"))
		}
		for _, tc := range []struct {
			rule  rules.Entry
			count int
		}{{requestRule, 1}, {responseRule, 2}} {
			got := previewWithQueue(207, nil, tc.rule, evs...)
			if got.MatchCount != tc.count {
				t.Fatalf("preview %s=%+v", tc.rule.ID, got)
			}
		}
		master, ok := e.Inventory().Get(testClient)
		if !ok || master.Role != "master" || master.PacketCount != 3 {
			t.Fatalf("master=%+v", master)
		}
		slave, ok := e.Inventory().Get(testServer)
		if !ok || slave.Role != "slave" || slave.PacketCount != 3 {
			t.Fatalf("slave=%+v", slave)
		}
	}
}

func TestPolicyDirectionIgnoresKind(t *testing.T) {
	for _, dir := range []flow.Direction{flow.DirForward, flow.DirReverse} {
		state := &flow.State{Key: modbusKey(502, dir)}
		want := "request"
		if dir == flow.DirReverse {
			want = "response"
		}
		for _, kind := range []string{"request", "response", "exception", "restart", "session"} {
			ctx, ok := evalContextFromDPIEvent(nil, state, &dpi.ParsedPacket{Proto: "tcp"}, dpi.Event{Proto: "modbus", Kind: kind}, "", "")
			if !ok || ctx.ICS.Direction != want {
				t.Fatalf("dir=%v kind=%s ctx=%+v", dir, kind, ctx)
			}
		}
	}
}
