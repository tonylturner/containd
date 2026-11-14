// SPDX-License-Identifier: Apache-2.0
package engine

import (
	"github.com/tonylturner/containd/pkg/dp/capture"
	"github.com/tonylturner/containd/pkg/dp/rules"
	"net"
	"testing"
)

func TestUDPOnGatedPortEntersSessionTable(t *testing.T) {
	p := runtimePairCases()[0]
	entry := runtimePairRule(p, "enforce")
	entry.Protocols = nil
	e := runtimePairEngine(t, rules.Snapshot{Default: rules.ActionAllow, DPIMode: "enforce", Firewall: []rules.Entry{entry}}, true)
	pkt := capture.Packet{SrcIP: net.ParseIP(testClient), DstIP: net.ParseIP(testServer), SrcPort: 41000, DstPort: 502,
		Proto: 17, Transport: "udp", Payload: []byte{1, 2, 3, 4}, Interface: "eth1"}
	pkt.Token = capture.NewToken(1, firstCommandTokens.Add(1))
	d := e.HandlePacket(pkt)
	e.sessions.mu.Lock()
	n := len(e.sessions.sessions)
	e.sessions.mu.Unlock()
	t.Logf("UDP/502 decision=%+v sessions=%d", d, n)
	if n != 0 {
		t.Errorf("a UDP datagram created a TCP session-table entry: %+v", d)
	}
}

func TestSessionOwnershipRequiresTCP(t *testing.T) {
	for _, p := range runtimePairCases() {
		t.Run(p.protocol, func(t *testing.T) {
			e := runtimePairEngine(t, rules.Snapshot{DPIMode: "enforce",
				Firewall: []rules.Entry{runtimePairRule(p, "enforce")}}, true)
			inlineHandshake(t, e, 41000, p.port)
			pkt := runtimePairPacket(p, false, 100, p.request)
			pkt.Proto, pkt.Transport = 17, "udp"
			state := wireServiceState(pkt)
			if sessionProtocol(&state) != "" || e.sessionOwnsState(pkt, &state) ||
				e.sessionOwnsConnection(pkt, nil) || e.rawSessionOwnsConnection(pkt, nil) {
				t.Fatal("UDP tuple borrowed TCP ownership")
			}
		})
	}
}
