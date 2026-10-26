// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

package events

import (
	"net"
	"testing"
	"time"

	"github.com/tonylturner/containd/pkg/dp/dpi"
	"github.com/tonylturner/containd/pkg/dp/flow"
)

func iecEvent(session, dir string) dpi.Event {
	return dpi.Event{FlowID: "wire-" + dir, Proto: "iec104", Kind: dir, Timestamp: time.Now(),
		Attributes: map[string]any{"session_id": session, "direction": dir}}
}

func stateOf(src, dst string, sport, dport uint16) *flow.State {
	return &flow.State{Key: flow.Key{SrcIP: parseIP(src), DstIP: parseIP(dst), SrcPort: sport, DstPort: dport, Proto: 6}}
}

func TestFlowsGroupIECBySessionAcrossDirections(t *testing.T) {
	s := NewStore(100)
	pkt := &dpi.ParsedPacket{Proto: "tcp"}
	s.Record(stateOf("10.0.0.2", "10.0.0.1", 2404, 40000), pkt, []dpi.Event{iecEvent("run-1", "response")})
	s.Record(stateOf("10.0.0.1", "10.0.0.2", 40000, 2404), pkt, []dpi.Event{iecEvent("run-1", "request")})
	// Same tuple, next incarnation: never merged with the first.
	s.Record(stateOf("10.0.0.1", "10.0.0.2", 40000, 2404), pkt, []dpi.Event{iecEvent("run-2", "request")})
	// A non-IEC flow groups by FlowID as before.
	s.Record(stateOf("10.0.0.1", "10.0.0.3", 40001, 502), pkt, []dpi.Event{{FlowID: "mb", Proto: "modbus", Kind: "request"}, {FlowID: "mb", Proto: "modbus", Kind: "request"}})
	flows := s.Flows(0)
	if len(flows) != 3 {
		t.Fatalf("flows = %+v", flows)
	}
	first := flows[0]
	if first.SessionID != "run-1" || first.FlowID != "run-1" || first.EventCount != 2 || first.SrcIP != "10.0.0.1" || first.DstPort != 2404 {
		t.Fatalf("session group = %+v, want both directions oriented client → server", first)
	}
	if flows[1].SessionID != "run-2" || flows[2].FlowID != "mb" || flows[2].SessionID != "" || flows[2].EventCount != 2 {
		t.Fatalf("flows = %+v", flows)
	}
	s.MarkAborted("run-1")
	flows = s.Flows(1)
	if len(flows) != 1 || flows[0].SessionID != "run-2" {
		t.Fatalf("aborted incarnation must be hidden before limit: %+v", flows)
	}
	if len(s.List(0)) != 5 {
		t.Fatal("aborted events must stay in List")
	}
}

func TestAbortedSetIsBounded(t *testing.T) {
	var a abortedSet
	for i := 0; i < maxAbortedSessions+10; i++ {
		a.add(string(rune('a'+i%26))+string(rune(i)), eventRing{})
	}
	if len(a.ids) != maxAbortedSessions || len(a.order) != maxAbortedSessions {
		t.Fatalf("aborted set size = %d/%d", len(a.ids), len(a.order))
	}
	// Entries no retained event names are pruned once the ring moved past.
	var b abortedSet
	b.add("gone", eventRing{events: []Event{{ID: 5}}})
	b.prune(eventRing{events: []Event{{ID: 7}}})
	if b.has("gone") {
		t.Fatal("stale aborted entry kept")
	}
	b.add("late", eventRing{events: []Event{{ID: 9}}})
	b.prune(eventRing{events: []Event{{ID: 9}}})
	if !b.has("late") {
		t.Fatal("entry pruned before the ring passed its mark")
	}
}

func parseIP(s string) net.IP { return net.ParseIP(s) }
