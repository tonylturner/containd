// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

package engine

import (
	"context"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/tonylturner/containd/pkg/dp/capture"
	"github.com/tonylturner/containd/pkg/dp/dpi"
	"github.com/tonylturner/containd/pkg/dp/flow"
	"github.com/tonylturner/containd/pkg/dp/rules"
)

const (
	testClient = "172.31.0.5"
	testServer = "172.30.0.4"
	ackPsh     = capture.TCPFlagACK | 0x08
)

type blockRecorder struct {
	mu    sync.Mutex
	flows []string
}

func (b *blockRecorder) BlockHostTemp(context.Context, net.IP, time.Duration) error { return nil }

func (b *blockRecorder) BlockFlowTemp(_ context.Context, src, dst net.IP, proto, dport string, _ time.Duration) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.flows = append(b.flows, src.String()+">"+dst.String()+"/"+proto+":"+dport)
	return nil
}

func (b *blockRecorder) blocked() []string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return append([]string(nil), b.flows...)
}

func segment(fromServer bool, seq uint32, flags uint8, payload []byte) capture.Packet {
	return connSegment(fromServer, 41000, 502, seq, flags, payload)
}

// connSegment builds a segment of the testClient:clientPort ->
// testServer:serverPort connection, sent by the server when fromServer.
func connSegment(fromServer bool, clientPort, serverPort uint16, seq uint32, flags uint8, payload []byte) capture.Packet {
	pkt := capture.Packet{
		Timestamp: time.Now().UTC(),
		Interface: "eth1",
		SrcIP:     net.ParseIP(testClient),
		DstIP:     net.ParseIP(testServer),
		SrcPort:   clientPort,
		DstPort:   serverPort,
		Proto:     6,
		Transport: "tcp",
		Payload:   payload,
		TCPSeq:    seq,
		HasTCPSeq: true,
		TCPFlags:  flags,
	}
	if fromServer {
		pkt.Interface = "eth0"
		pkt.SrcIP, pkt.DstIP = pkt.DstIP, pkt.SrcIP
		pkt.SrcPort, pkt.DstPort = pkt.DstPort, pkt.SrcPort
	}
	return pkt
}

func newOrientationEngine(t *testing.T) *Engine {
	t.Helper()
	e, err := New(Config{Capture: capture.Config{Interfaces: []string{"eth0", "eth1"}}})
	if err != nil {
		t.Fatalf("new engine: %v", err)
	}
	return e
}

func TestTrackFlowOrientsReplies(t *testing.T) {
	cases := []struct {
		name    string
		packets []capture.Packet
	}{
		{"handshake", []capture.Packet{
			segment(false, 100, capture.TCPFlagSYN, nil),
			segment(true, 500, capture.TCPFlagSYN|capture.TCPFlagACK, nil),
		}},
		// The SYN-ACK alone proves the server side, even when it is the
		// first packet the engine sees.
		{"syn-ack first", []capture.Packet{
			segment(true, 500, capture.TCPFlagSYN|capture.TCPFlagACK, nil),
			segment(false, 100, capture.TCPFlagACK, nil),
		}},
		{"mid-stream, opener first", []capture.Packet{
			segment(false, 100, ackPsh, modbusADU(1, 3, 0, 2)),
			segment(true, 500, ackPsh, nil),
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			e := newOrientationEngine(t)
			var client, server *flow.State
			for _, p := range tc.packets {
				st := e.trackFlow(p, time.Now())
				if p.SrcIP.String() == testClient {
					client = st
				} else {
					server = st
				}
			}
			if client.Key.Dir != flow.DirForward || server.Key.Dir != flow.DirReverse {
				t.Fatalf("client dir=%d server dir=%d, want forward/reverse", client.Key.Dir, server.Key.Dir)
			}
			if again := e.trackFlow(segment(true, 500, ackPsh, nil), time.Now()); again != server {
				t.Fatal("reply direction did not reuse its state")
			}
			if len(e.flows) != 2 {
				t.Fatalf("flows = %d, want 2", len(e.flows))
			}
		})
	}
}

func TestTrackFlowHandshakeReorients(t *testing.T) {
	e := newOrientationEngine(t)
	// Mid-stream capture saw the server first and took it as the opener.
	if st := e.trackFlow(segment(true, 500, ackPsh, nil), time.Now()); st.Key.Dir != flow.DirForward {
		t.Fatalf("first-seen dir = %d, want forward", st.Key.Dir)
	}
	e.trackFlow(segment(false, 100, capture.TCPFlagACK, nil), time.Now())
	// A new connection on the tuple corrects the orientation.
	if st := e.trackFlow(segment(false, 1000, capture.TCPFlagSYN, nil), time.Now()); st.Key.Dir != flow.DirForward {
		t.Fatalf("SYN sender dir = %d, want forward", st.Key.Dir)
	}
	if st := e.trackFlow(segment(true, 5000, ackPsh, nil), time.Now()); st.Key.Dir != flow.DirReverse {
		t.Fatalf("server dir after SYN = %d, want reverse", st.Key.Dir)
	}
	if len(e.flows) != 2 {
		t.Fatalf("flows = %d, want 2", len(e.flows))
	}
}

func TestReplyEvaluatedWithConnectionOrientation(t *testing.T) {
	e := newOrientationEngine(t)
	e.trackFlow(segment(false, 100, capture.TCPFlagSYN, nil), time.Now())
	reply := segment(true, 500, ackPsh, nil)
	state := e.trackFlow(reply, time.Now())
	pkt := &dpi.ParsedPacket{Proto: "tcp", SrcPort: reply.SrcPort, DstPort: reply.DstPort}

	if got := servicePort(state, pkt); got != 502 {
		t.Fatalf("servicePort(reply) = %d, want 502", got)
	}
	ev := dpi.Event{Proto: "modbus", Kind: "request", Attributes: map[string]any{"function_code": uint8(3)}}
	ctx, ok := evalContextFromDPIEvent(nil, state, pkt, ev, "lan", "wan")
	if !ok {
		t.Fatal("reply event not evaluable")
	}
	if ctx.SrcIP.String() != testClient || ctx.DstIP.String() != testServer || ctx.Port != "502" || ctx.SrcZone != "lan" || ctx.DstZone != "wan" {
		t.Fatalf("reply context = %+v, want %s -> %s:502 lan->wan", ctx, testClient, testServer)
	}
	if ctx.ICS.Direction != "response" {
		t.Fatalf("ICS direction = %q, want response for a message from the server", ctx.ICS.Direction)
	}
}

// TestPersistentModbusUnderDefaultDeny mirrors the smoke policy: default
// DENY, an allow for FC3 reads and a deny for FC6 writes from the client
// to the server, enforce mode. Read replies must not be blocked; the write
// must block the client -> server flow only. The echoed write reply
// matches the deny rule too, so the write yields two rule hits, both
// blocking the request tuple.
func TestPersistentModbusUnderDefaultDeny(t *testing.T) {
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
	match := rules.Entry{
		Sources:      []string{testClient + "/32"},
		Destinations: []string{testServer + "/32"},
		Protocols:    []rules.Protocol{{Name: "tcp", Port: "502"}},
		Log:          true,
	}
	read, write := match, match
	read.ID, read.Action = "read", rules.ActionAllow
	read.ICS = rules.ICSPredicate{Protocol: "modbus", FunctionCode: []uint8{3}, ReadOnly: true}
	write.ID, write.Action = "write-deny", rules.ActionDeny
	write.ICS = rules.ICSPredicate{Protocol: "modbus", FunctionCode: []uint8{6}, WriteOnly: true}
	// IDS on (the shipped default config) inspects every flow, replies
	// included.
	e.LoadRules(rules.Snapshot{
		Default:  rules.ActionDeny,
		Firewall: []rules.Entry{read, write},
		IDS:      rules.IDSConfig{Enabled: true},
	})

	readReq, readResp := modbusADU(10, 3, 0, 2), []byte{0, 10, 0, 0, 0, 7, 1, 3, 4, 0, 0, 0, 1}
	e.handlePacket(segment(false, 100, capture.TCPFlagSYN, nil))
	e.handlePacket(segment(true, 500, capture.TCPFlagSYN|capture.TCPFlagACK, nil))
	e.handlePacket(segment(false, 100, ackPsh, readReq))
	e.handlePacket(segment(true, 500, ackPsh, readResp))
	if got := up.blocked(); len(got) != 0 {
		t.Fatalf("allowed read or its reply was blocked: %v", got)
	}

	write6 := modbusADU(11, 6, 1, 0x1234)
	e.handlePacket(segment(false, 112, ackPsh, write6))
	want := testClient + ">" + testServer + "/tcp:502"
	if got := up.blocked(); len(got) != 1 || got[0] != want {
		t.Fatalf("blocks after write = %v, want [%s]", got, want)
	}
	e.handlePacket(segment(true, 513, ackPsh, write6))
	if got := up.blocked(); len(got) != 2 || got[0] != want || got[1] != want {
		t.Fatalf("blocks after the echoed reply = %v, want [%s %s]", got, want, want)
	}
	if got := ruleHits(e, "write-deny"); got != 2 {
		t.Fatalf("write-deny rule hits = %d, want 2", got)
	}

	// Event wire fields stay as captured: the reply reads server -> client.
	var replies int
	for _, ev := range e.Events().List(0) {
		if ev.Proto == "modbus" && ev.SrcIP == testServer {
			replies++
			if ev.DstIP != testClient || ev.SrcPort != 502 || ev.DstPort != 41000 {
				t.Fatalf("reply event wire fields = %+v", ev)
			}
		}
		if ev.Kind == "firewall.rule.hit" && strings.HasPrefix(ev.SrcIP, "172.30.") {
			t.Fatalf("rule hit evaluated with the reply orientation: %+v", ev)
		}
	}
	if replies != 2 {
		t.Fatalf("reply events = %d, want 2", replies)
	}
}

// TestReplyInspectedByServicePort checks that a rule constraining the
// server port also steers the reply direction through DPI.
func TestReplyInspectedByServicePort(t *testing.T) {
	e := newModbusInspectEngine(t)
	e.handlePacket(segment(false, 100, capture.TCPFlagSYN, nil))
	e.handlePacket(segment(true, 500, ackPsh, []byte{0, 10, 0, 0, 0, 7, 1, 3, 4, 0, 0, 0, 1}))
	if got := modbusEventsOldestFirst(e); len(got) != 1 || got[0].SrcIP != testServer {
		t.Fatalf("reply events = %+v, want one from %s", got, testServer)
	}
}
