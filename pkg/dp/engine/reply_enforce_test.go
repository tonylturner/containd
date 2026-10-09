// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

package engine

import (
	"net"
	"strconv"
	"testing"

	"github.com/tonylturner/containd/pkg/dp/capture"
	"github.com/tonylturner/containd/pkg/dp/flow"
	"github.com/tonylturner/containd/pkg/dp/rules"
)

// DNP3 link frames between master 1 (the client) and outstation 10 (the
// server), with valid CRCs.
var (
	// FC1 read, class 0 (g60v1, all objects).
	dnp3Read = []byte{0x05, 0x64, 0x0b, 0xc4, 0x0a, 0x00, 0x01, 0x00, 0xac, 0xd1, 0xc0, 0xc1, 0x01, 0x3c, 0x01, 0x06, 0xf9, 0x73}
	// FC129 response, no objects.
	dnp3Response = []byte{0x05, 0x64, 0x0a, 0x44, 0x01, 0x00, 0x0a, 0x00, 0x6e, 0x25, 0xc0, 0xc1, 0x81, 0x00, 0x00, 0x74, 0x2a}
	// FC130 unsolicited response, no objects.
	dnp3Unsolicited = []byte{0x05, 0x64, 0x0a, 0x44, 0x01, 0x00, 0x0a, 0x00, 0x6e, 0x25, 0xc0, 0xf0, 0x82, 0x00, 0x00, 0x44, 0x66}
)

const dnp3Port = 20000

// newEnforceEngine returns an AF_PACKET-style engine in enforce mode, with
// IDS on so that every flow, replies included, is inspected.
func newEnforceEngine(t *testing.T, def rules.Action, entries ...rules.Entry) (*Engine, *blockRecorder) {
	t.Helper()
	up := &blockRecorder{}
	e, err := New(Config{
		Capture:    capture.Config{Interfaces: []string{"eth0", "eth1"}},
		Enforce:    EnforceConfig{Enabled: true, Updater: up},
		DPIEnabled: true,
		DPIMode:    "enforce",
	})
	if err != nil {
		t.Fatalf("new engine: %v", err)
	}
	e.LoadRules(rules.Snapshot{Default: def, Firewall: entries, IDS: rules.IDSConfig{Enabled: true}})
	return e, up
}

// clientToServer is a logged rule scoped to the test connection's
// addresses and server port.
func clientToServer(id string, port string, action rules.Action, ics rules.ICSPredicate) rules.Entry {
	return rules.Entry{
		ID:           id,
		Sources:      []string{testClient + "/32"},
		Destinations: []string{testServer + "/32"},
		Protocols:    []rules.Protocol{{Name: "tcp", Port: port}},
		ICS:          ics,
		Action:       action,
		Log:          true,
	}
}

func ruleHits(e *Engine, ruleID string) int {
	var n int
	for _, ev := range e.Events().List(0) {
		if ev.Kind == "firewall.rule.hit" && ev.Attributes["ruleId"] == ruleID {
			n++
		}
	}
	return n
}

func protoEvents(e *Engine, proto string) int {
	var n int
	for _, ev := range e.Events().List(0) {
		if ev.Proto == proto {
			n++
		}
	}
	return n
}

// replyVerdict reports whether a verdict is cached for the server's
// direction of the connection from clientPort.
func replyVerdict(e *Engine, clientPort, serverPort uint16) bool {
	key := flow.Key{
		SrcIP:   net.ParseIP(testServer),
		DstIP:   net.ParseIP(testClient),
		SrcPort: serverPort,
		DstPort: clientPort,
		Proto:   6,
		Dir:     flow.DirReverse,
	}
	_, ok := e.verdictCache.Get(key.Hash())
	return ok
}

func handshake(e *Engine, clientPort, serverPort uint16) {
	e.handlePacket(connSegment(false, clientPort, serverPort, 100, capture.TCPFlagSYN, nil))
	e.handlePacket(connSegment(true, clientPort, serverPort, 500, capture.TCPFlagSYN|capture.TCPFlagACK, nil))
}

// TestDNP3ReplyNotEnforcedUnderDefaultDeny is the AF_PACKET re-poll case:
// the master's FC1 read is allowed, the outstation's FC129 reply matches
// no rule, and the default DENY must not block the master's next polls.
func TestDNP3ReplyNotEnforcedUnderDefaultDeny(t *testing.T) {
	e, up := newEnforceEngine(t, rules.ActionDeny,
		clientToServer("dnp3-read", "20000", rules.ActionAllow, rules.ICSPredicate{Protocol: "dnp3", FunctionCode: []uint8{1}}))

	handshake(e, 41000, dnp3Port)
	e.handlePacket(connSegment(false, 41000, dnp3Port, 100, ackPsh, dnp3Read))
	e.handlePacket(connSegment(true, 41000, dnp3Port, 500, ackPsh, dnp3Response))
	if got := up.blocked(); len(got) != 0 {
		t.Fatalf("blocks after the read and its reply = %v, want none", got)
	}
	if replyVerdict(e, 41000, dnp3Port) {
		t.Fatal("the reply produced a verdict")
	}

	// A second poll on the same connection, then on a new one.
	e.handlePacket(connSegment(false, 41000, dnp3Port, 118, ackPsh, dnp3Read))
	e.handlePacket(connSegment(true, 41000, dnp3Port, 517, ackPsh, dnp3Response))
	handshake(e, 41001, dnp3Port)
	e.handlePacket(connSegment(false, 41001, dnp3Port, 100, ackPsh, dnp3Read))
	e.handlePacket(connSegment(true, 41001, dnp3Port, 500, ackPsh, dnp3Response))
	if got := up.blocked(); len(got) != 0 {
		t.Fatalf("blocks after the re-polls = %v, want none", got)
	}
	if got := protoEvents(e, "dnp3"); got != 6 {
		t.Fatalf("dnp3 events = %d, want 6", got)
	}
	if got := ruleHits(e, "dnp3-read"); got != 3 {
		t.Fatalf("dnp3-read rule hits = %d, want 3 (the polls only)", got)
	}
}

// TestDNP3UnsolicitedNotEnforced: an outstation's FC130 unsolicited
// response matches no rule and gets no verdict.
func TestDNP3UnsolicitedNotEnforced(t *testing.T) {
	e, up := newEnforceEngine(t, rules.ActionDeny,
		clientToServer("dnp3-read", "20000", rules.ActionAllow, rules.ICSPredicate{Protocol: "dnp3", FunctionCode: []uint8{1}}))

	handshake(e, 41000, dnp3Port)
	e.handlePacket(connSegment(true, 41000, dnp3Port, 500, ackPsh, dnp3Unsolicited))
	if got := protoEvents(e, "dnp3"); got != 1 {
		t.Fatalf("dnp3 events = %d, want 1", got)
	}
	if got := up.blocked(); len(got) != 0 {
		t.Fatalf("blocks = %v, want none", got)
	}
	if replyVerdict(e, 41000, dnp3Port) {
		t.Fatal("the unsolicited response produced a verdict")
	}
}

// TestExplicitResponseRuleEnforcesReply: a deny rule that names the
// response direction still enforces on a matching reply, and blocks the
// request tuple. A Modbus reply is a response even though its decoder
// kind is "request".
func TestExplicitResponseRuleEnforcesReply(t *testing.T) {
	cases := []struct {
		name    string
		port    uint16
		ics     rules.ICSPredicate
		request []byte
		reply   []byte
	}{
		{"dnp3 unsolicited", dnp3Port,
			rules.ICSPredicate{Protocol: "dnp3", FunctionCode: []uint8{130}, Direction: "response"},
			nil, dnp3Unsolicited},
		{"modbus read reply", 502,
			rules.ICSPredicate{Protocol: "modbus", FunctionCode: []uint8{3}, Direction: "response"},
			modbusADU(10, 3, 0, 2), []byte{0, 10, 0, 0, 0, 7, 1, 3, 4, 0, 0, 0, 1}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			port := strconv.Itoa(int(tc.port))
			e, up := newEnforceEngine(t, rules.ActionAllow, clientToServer("deny-reply", port, rules.ActionDeny, tc.ics))
			handshake(e, 41000, tc.port)
			if tc.request != nil {
				e.handlePacket(connSegment(false, 41000, tc.port, 100, ackPsh, tc.request))
				if got := up.blocked(); len(got) != 0 {
					t.Fatalf("the request was blocked by a response rule: %v", got)
				}
			}
			e.handlePacket(connSegment(true, 41000, tc.port, 500, ackPsh, tc.reply))
			want := testClient + ">" + testServer + "/tcp:" + port
			if got := up.blocked(); len(got) != 1 || got[0] != want {
				t.Fatalf("blocks = %v, want [%s]", got, want)
			}
			if got := ruleHits(e, "deny-reply"); got != 1 {
				t.Fatalf("deny-reply rule hits = %d, want 1", got)
			}
			if !replyVerdict(e, 41000, tc.port) {
				t.Fatal("no verdict cached for the denied reply")
			}
		})
	}
}

// TestModbusExceptionReplyNotEnforced: the read is allowed by a
// request-direction rule, so the server's exception reply matches no rule
// and the default DENY does not apply to it.
func TestModbusExceptionReplyNotEnforced(t *testing.T) {
	e, up := newEnforceEngine(t, rules.ActionDeny,
		clientToServer("read", "502", rules.ActionAllow, rules.ICSPredicate{Protocol: "modbus", FunctionCode: []uint8{3}, Direction: "request"}))

	handshake(e, 41000, 502)
	e.handlePacket(connSegment(false, 41000, 502, 100, ackPsh, modbusADU(10, 3, 0, 2)))
	// Exception 0x83, code 2 (illegal data address).
	e.handlePacket(connSegment(true, 41000, 502, 500, ackPsh, []byte{0, 10, 0, 0, 0, 3, 1, 0x83, 2}))
	if got := protoEvents(e, "modbus"); got != 2 {
		t.Fatalf("modbus events = %d, want 2", got)
	}
	if got := up.blocked(); len(got) != 0 {
		t.Fatalf("blocks = %v, want none", got)
	}
	if replyVerdict(e, 41000, 502) {
		t.Fatal("the exception reply produced a verdict")
	}
	if got := ruleHits(e, "read"); got != 1 {
		t.Fatalf("read rule hits = %d, want 1 (the request only)", got)
	}
}

// TestRequestStillGetsDefault: a request from the opener that matches no
// rule still gets the default DENY, even when its decoder calls it a
// response.
func TestRequestStillGetsDefault(t *testing.T) {
	e, up := newEnforceEngine(t, rules.ActionDeny,
		clientToServer("dnp3-read", "20000", rules.ActionAllow, rules.ICSPredicate{Protocol: "dnp3", FunctionCode: []uint8{1}}))

	handshake(e, 41000, dnp3Port)
	// The master sends an outstation's frame: FC130 from the opener.
	e.handlePacket(connSegment(false, 41000, dnp3Port, 100, ackPsh, dnp3Unsolicited))
	want := testClient + ">" + testServer + "/tcp:20000"
	if got := up.blocked(); len(got) != 1 || got[0] != want {
		t.Fatalf("blocks = %v, want [%s]", got, want)
	}
}
