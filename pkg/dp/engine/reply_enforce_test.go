// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

package engine

import (
	"context"
	"fmt"
	"net"
	"strconv"
	"testing"

	"github.com/tonylturner/containd/pkg/dp/capture"
	"github.com/tonylturner/containd/pkg/dp/conntrack"
	"github.com/tonylturner/containd/pkg/dp/flow"
	"github.com/tonylturner/containd/pkg/dp/rules"
	"github.com/tonylturner/containd/pkg/dp/session"
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

// newEnforceEngine returns an engine in enforce mode, with
// IDS on so that every flow, replies included, is inspected.
func newEnforceEngine(t *testing.T, def rules.Action, entries ...rules.Entry) (*Engine, *blockRecorder) {
	t.Helper()
	up := &blockRecorder{}
	e, err := New(Config{
		Capture:    capture.Config{Interfaces: []string{"eth0", "eth1"}},
		Enforce:    EnforceConfig{ClearMark: noPolicyMarks, Enabled: true, Updater: up},
		DPIEnabled: true,
		DPIMode:    "enforce",
	})
	if err != nil {
		t.Fatalf("new engine: %v", err)
	}
	startBlockWorker(t, e)
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

func sendInline(e *Engine, pkt capture.Packet) capture.Decision {
	pkt.Token = capture.NewToken(1, firstCommandTokens.Add(1))
	d := e.HandlePacket(pkt)
	if d.Action != capture.Hold {
		v := capture.VerdictRepeat
		if d.Action == capture.Drop {
			v = capture.VerdictDrop
		}
		e.hooks.onVerdict(pkt.Token, v, nil)
	}
	for _, r := range d.Resolved {
		e.hooks.onVerdict(r.Token, r.Verdict, nil)
	}
	return d
}

func inlineHandshake(t *testing.T, e *Engine, clientPort, serverPort uint16) {
	t.Helper()
	e.sessions.injector = &session.Fake{}
	e.sessions.health.clear(faultInjector)
	e.sessions.ctDelete = func(context.Context, conntrack.DeleteRequest) error { return nil }
	syn := connSegment(false, clientPort, serverPort, 100, capture.TCPFlagSYN, nil)
	ack := connSegment(true, clientPort, serverPort, 500, capture.TCPFlagSYN|capture.TCPFlagACK, nil)
	ack.TCP.Ack = 100
	for _, pkt := range []capture.Packet{syn, ack} {
		if d := sendInline(e, pkt); d.Action != capture.Repeat {
			t.Fatalf("handshake=%+v", d)
		}
	}
}

func decodedProtocolEvents(e *Engine, proto string) int {
	n := 0
	for _, ev := range e.Events().List(0) {
		if ev.Proto == proto && (ev.Kind == "request" || ev.Kind == "response" || ev.Kind == "exception") {
			n++
		}
	}
	return n
}

func handshake(e *Engine, clientPort, serverPort uint16) {
	e.handlePacket(connSegment(false, clientPort, serverPort, 100, capture.TCPFlagSYN, nil))
	e.handlePacket(connSegment(true, clientPort, serverPort, 500, capture.TCPFlagSYN|capture.TCPFlagACK, nil))
}

// TestDNP3ReplyNotEnforcedUnderDefaultDeny is the inline paired re-poll case:
// the master's FC1 read is allowed, the outstation's FC129 reply matches
// no rule, and the default DENY must not block the master's next polls.
func TestDNP3ReplyNotEnforcedUnderDefaultDeny(t *testing.T) {
	e, up := newEnforceEngine(t, rules.ActionDeny,
		clientToServer("dnp3-read", "20000", rules.ActionAllow, rules.ICSPredicate{Protocol: "dnp3", FunctionCode: []uint8{1}}))

	inlineHandshake(t, e, 41000, dnp3Port)
	sendInline(e, connSegment(false, 41000, dnp3Port, 100, ackPsh, dnp3Read))
	sendInline(e, connSegment(true, 41000, dnp3Port, 500, ackPsh, dnp3Response))
	if got := up.blockedAfter(e); len(got) != 0 {
		t.Fatalf("blocks after the read and its reply = %v, want none", got)
	}
	if replyVerdict(e, 41000, dnp3Port) {
		t.Fatal("the reply produced a verdict")
	}

	// A second poll on the same connection, then on a new one.
	sendInline(e, connSegment(false, 41000, dnp3Port, 118, ackPsh, dnp3Read))
	sendInline(e, connSegment(true, 41000, dnp3Port, 517, ackPsh, dnp3Response))
	inlineHandshake(t, e, 41001, dnp3Port)
	sendInline(e, connSegment(false, 41001, dnp3Port, 100, ackPsh, dnp3Read))
	sendInline(e, connSegment(true, 41001, dnp3Port, 500, ackPsh, dnp3Response))
	if got := up.blockedAfter(e); len(got) != 0 {
		t.Fatalf("blocks after the re-polls = %v, want none", got)
	}
	if got := decodedProtocolEvents(e, "dnp3"); got != 6 {
		t.Fatalf("dnp3 events = %d, want 6", got)
	}
	if got := ruleHits(e, "dnp3-read"); got != 3 {
		t.Fatalf("dnp3-read rule hits = %d, want 3 (the polls only)", got)
	}
}

// An outstation's FC130 unsolicited response needs an explicit autonomous rule,
// regardless of the ordinary default; it never borrows solicited authority.
func TestDNP3UnsolicitedNotEnforced(t *testing.T) {
	for _, def := range []rules.Action{rules.ActionAllow, rules.ActionDeny} {
		for _, explicit := range []bool{false, true} {
			t.Run(string(def)+fmt.Sprint(explicit), func(t *testing.T) {
				entries := []rules.Entry{clientToServer("read", "20000", rules.ActionAllow, rules.ICSPredicate{Protocol: "dnp3", FunctionCode: []uint8{1}})}
				if explicit {
					entries = append(entries, clientToServer("autonomous", "20000", rules.ActionAllow, rules.ICSPredicate{Protocol: "dnp3", MessageClass: "autonomous", Direction: "response"}))
				}
				e, up := newEnforceEngine(t, def, entries...)
				inlineHandshake(t, e, 41000, dnp3Port)
				d := sendInline(e, connSegment(true, 41000, dnp3Port, 500, ackPsh, dnp3Unsolicited))
				want := capture.Drop
				if explicit {
					want = capture.Repeat
				}
				if d.Action != want || !explicit && d.Reason != string(autonomousRequired) {
					t.Fatalf("autonomous decision=%+v, explicit=%t", d, explicit)
				}
				if got := decodedProtocolEvents(e, "dnp3"); got != 1 {
					t.Fatalf("decoded events=%d, want1", got)
				}
				if got := up.blockedAfter(e); len(got) != 0 {
					t.Fatalf("blocks=%v", got)
				}
				if replyVerdict(e, 41000, dnp3Port) {
					t.Fatal("reply wrote legacy verdict cache")
				}
			})
		}
	}
}

// TestExplicitResponseRuleEnforcesReply: a deny rule that names the
// response direction still denies the matching reply and retires the session.
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
			allow := clientToServer("request", port, rules.ActionAllow, rules.ICSPredicate{Protocol: tc.ics.Protocol, Direction: "request"})
			e, up := newEnforceEngine(t, rules.ActionAllow, clientToServer("deny-reply", port, rules.ActionDeny, tc.ics), allow)
			inlineHandshake(t, e, 41000, tc.port)
			if tc.request != nil {
				sendInline(e, connSegment(false, 41000, tc.port, 100, ackPsh, tc.request))
				if got := up.blockedAfter(e); len(got) != 0 {
					t.Fatalf("the request was blocked by a response rule: %v", got)
				}
			}
			if d := sendInline(e, connSegment(true, 41000, tc.port, 500, ackPsh, tc.reply)); d.Action != capture.Drop {
				t.Fatalf("denied reply = %+v", d)
			}
			if got := up.blockedAfter(e); len(got) != 0 {
				t.Fatalf("DPI blocks = %v, want none", got)
			}
			if got := ruleHits(e, "deny-reply"); got != 1 {
				t.Fatalf("deny-reply rule hits = %d, want 1", got)
			}
			if d := sendInline(e, connSegment(false, 41000, tc.port, 112, ackPsh, modbusADU(11, 3, 0, 2))); d.Action != capture.Drop {
				t.Fatalf("denied session reopened by later payload: %+v", d)
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

	inlineHandshake(t, e, 41000, 502)
	sendInline(e, connSegment(false, 41000, 502, 100, ackPsh, modbusADU(10, 3, 0, 2)))
	// Exception 0x83, code 2 (illegal data address).
	sendInline(e, connSegment(true, 41000, 502, 500, ackPsh, []byte{0, 10, 0, 0, 0, 3, 1, 0x83, 2}))
	if got := decodedProtocolEvents(e, "modbus"); got != 2 {
		t.Fatalf("modbus events = %d, want 2", got)
	}
	if got := up.blockedAfter(e); len(got) != 0 {
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

	inlineHandshake(t, e, 41000, dnp3Port)
	// The master sends an outstation's frame: FC130 from the opener.
	if d := sendInline(e, connSegment(false, 41000, dnp3Port, 100, ackPsh, dnp3Unsolicited)); d.Action != capture.Drop {
		t.Fatalf("default deny = %+v", d)
	}
	if got := up.blockedAfter(e); len(got) != 0 {
		t.Fatalf("DPI blocks = %v, want none", got)
	}
}
