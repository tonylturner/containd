// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

package engine

import (
	"testing"

	"github.com/tonylturner/containd/pkg/dp/capture"
	"github.com/tonylturner/containd/pkg/dp/dpi"
	"github.com/tonylturner/containd/pkg/dp/rules"
)

// apdu builds an IEC 60870-5-104 I-frame with one information object.
func apdu(typeID, cot byte, ca uint16, ioa uint32, elem ...byte) []byte {
	body := []byte{typeID, 0x01, cot, 0x00, byte(ca), byte(ca >> 8), byte(ioa), byte(ioa >> 8), byte(ioa >> 16)}
	body = append(body, elem...)
	return append([]byte{0x68, byte(4 + len(body)), 0, 0, 0, 0}, body...)
}

var (
	startdtAct = []byte{0x68, 0x04, 0x07, 0, 0, 0}
	stopdtAct  = []byte{0x68, 0x04, 0x13, 0, 0, 0}
)

// euSnapshot is the spec §12.4 EU rule block.
func euSnapshot() rules.Snapshot {
	scope := func(e rules.Entry) rules.Entry {
		e.Sources, e.Destinations = []string{"10.60.60.10/32"}, []string{"10.30.30.30/32"}
		e.Protocols = []rules.Protocol{{Name: "tcp", Port: "2404"}}
		e.Log = true
		return e
	}
	return rules.Snapshot{Default: rules.ActionAllow, Firewall: []rules.Entry{
		scope(rules.Entry{ID: "cc-rtu-iec104-session", Action: rules.ActionAllow,
			ICS: rules.ICSPredicate{Protocol: "iec104", ReadOnly: true, Mode: "enforce"}}),
		scope(rules.Entry{ID: "cc-rtu-breaker-command", Action: rules.ActionAllow,
			ICS: rules.ICSPredicate{Protocol: "iec104", TypeIDs: []int{46}, Classes: []string{"control"}, Direction: "request",
				CA: []uint16{1}, IOA: []rules.IOARange{{Start: 2001, End: 2001}}, Mode: "enforce"}}),
		scope(rules.Entry{ID: "rtu-cc-command-confirm", Action: rules.ActionAllow,
			ICS: rules.ICSPredicate{Protocol: "iec104", Classes: []string{"control"}, Direction: "response", Mode: "enforce"}}),
		{ID: "deny-other-iec104", Protocols: []rules.Protocol{{Name: "tcp", Port: "2404"}}, Action: rules.ActionDeny, Log: true,
			ICS: rules.ICSPredicate{Protocol: "iec104", Mode: "enforce"}},
	}}
}

// TestIECRealDecoderAndEvaluator runs the EU policy end to end through the
// registered IEC104 decoder and the rule evaluator.
func TestIECRealDecoderAndEvaluator(t *testing.T) {
	h := newIECHarness(t, "enforce")
	h.e.dpiMgr = dpi.NewManager(DefaultDecoders()...)
	h.e.iec.dpi = h.e.dpiMgr
	h.e.iec.newPolicy = newRulesPolicy
	h.e.LoadRules(euSnapshot())
	h.handshake()
	steps := []struct {
		name       string
		fromClient bool
		payload    []byte
	}{
		{"STARTDT act", true, startdtAct},
		{"STARTDT con", false, startdtCon},
		{"GI act", true, apdu(100, 6, 1, 0, 20)},
		{"GI con", false, apdu(100, 7, 1, 0, 20)},
		{"spontaneous double point", false, apdu(3, 3, 1, 1001, 0x02)},
		{"select breaker", true, apdu(46, 6, 1, 2001, 0x81)},
		{"select confirmation", false, apdu(46, 7, 1, 2001, 0x81)},
		{"execute breaker", true, apdu(46, 6, 1, 2001, 0x01)},
		{"STOPDT act (read-only, alerted)", true, stopdtAct},
	}
	for _, s := range steps {
		if _, d := h.send(s.fromClient, s.payload); d.Action != capture.Accept {
			t.Fatalf("%s = %+v, want Accept; decisions %+v", s.name, d, h.eventsOf("ics.decision"))
		}
	}
	sawStop := false
	for _, ev := range h.eventsOf("signature_match") {
		sawStop = sawStop || ev.Attributes["signature_id"] == "IEC104-STOPDT"
	}
	if !sawStop {
		t.Fatal("STOPDT passed without its alert signature")
	}
	// Wrong IOA, wrong CA, and monitor data sent by the client are denied.
	for _, bad := range []struct {
		name    string
		payload []byte
		reason  string
	}{
		{"wrong IOA", apdu(46, 6, 1, 2002, 0x01), "rule"},
		{"wrong CA", apdu(46, 6, 2, 2001, 0x01), "rule"},
		{"broadcast CA", apdu(46, 6, 65535, 2001, 0x01), "broadcast"},
		{"client sends monitor data", apdu(3, 3, 1, 1001, 0x02), "role"},
	} {
		h2 := newIECHarness(t, "enforce")
		h2.e.dpiMgr = dpi.NewManager(DefaultDecoders()...)
		h2.e.iec.dpi = h2.e.dpiMgr
		h2.e.iec.newPolicy = newRulesPolicy
		h2.e.LoadRules(euSnapshot())
		h2.handshake()
		h2.send(true, startdtAct)
		if _, d := h2.send(true, bad.payload); d.Action != capture.Drop {
			t.Fatalf("%s = %+v, want Drop", bad.name, d)
		}
		var denied map[string]any
		for _, ev := range h2.eventsOf("ics.decision") {
			if ev.Attributes["decision"] == "deny" {
				denied = ev.Attributes
			}
		}
		if denied == nil || denied["reason"] != bad.reason {
			t.Fatalf("%s: deny decision = %v, want reason %s", bad.name, denied, bad.reason)
		}
		if got := h2.outcomes(); len(got) == 0 || got[0] != "aborted" {
			t.Fatalf("%s: outcomes = %v", bad.name, got)
		}
	}
}
