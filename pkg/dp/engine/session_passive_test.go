// SPDX-License-Identifier: Apache-2.0
package engine

import (
	"github.com/tonylturner/containd/pkg/dp/capture"
	"github.com/tonylturner/containd/pkg/dp/rules"
	"github.com/tonylturner/containd/pkg/dp/session"
	"testing"
)

func TestPassiveGenericSessionAbortedOnInstall(t *testing.T) {
	p := runtimePairCases()[0]
	snap := rules.Snapshot{Default: rules.ActionDeny, DPIMode: "enforce", Firewall: []rules.Entry{runtimePairRule(p, "enforce")}}
	e := runtimePairEngine(t, snap, true)
	handshake(e, 41000, p.port)
	req := connSegment(false, 41000, p.port, 100, ackPsh, p.request)
	e.handlePacket(req)
	s := runtimePairOwner(t, e, p)
	e.sessions.mu.Lock()
	mode, before := s.mode, s.state
	e.sessions.mu.Unlock()
	e.LoadRules(snap) // identical policy
	drainResetWorker(t, e)
	e.sessions.mu.Lock()
	after := s.state
	e.sessions.mu.Unlock()
	resets := len(e.sessions.injector.(*session.Fake).Resets())
	t.Logf("mode=%s state %d -> %d resets=%d", mode, before, after, resets)
	if after == sessionAborted {
		t.Errorf("re-installing the same policy aborted a passive %s session (resets injected=%d)", mode, resets)
	}
}

func passiveEstablishedHandshake(e *Engine, client, server uint16) {
	e.handlePacket(connSegment(false, client, server, 100, capture.TCPFlagSYN, nil))
	ack := connSegment(true, client, server, 500, capture.TCPFlagSYN|capture.TCPFlagACK, nil)
	ack.TCP.Ack = 100
	e.handlePacket(ack)
}

// Probe: passive capture, enforce-mode rule, valid handshake.
func TestPassiveEstablishedSessionAbortedOnInstall(t *testing.T) {
	for _, p := range runtimePairCases()[:2] {
		t.Run(p.protocol, func(t *testing.T) {
			snap := rules.Snapshot{Default: rules.ActionDeny, DPIMode: "enforce", Firewall: []rules.Entry{runtimePairRule(p, "enforce")}}
			e := runtimePairEngine(t, snap, true)
			passiveEstablishedHandshake(e, 41000, p.port)
			d := e.handlePacket(connSegment(false, 41000, p.port, 100, ackPsh, p.request))
			s := runtimePairOwner(t, e, p)
			e.sessions.mu.Lock()
			mode, before := s.mode, s.state
			e.sessions.mu.Unlock()
			e.LoadRules(snap)
			drainResetWorker(t, e)
			e.sessions.mu.Lock()
			after := s.state
			e.sessions.mu.Unlock()
			resets := e.sessions.injector.(*session.Fake).Resets()
			next := e.handlePacket(connSegment(true, 41000, p.port, 500, ackPsh, p.reply))
			t.Logf("request decision=%+v mode=%s state %d -> %d resets=%d next packet=%+v events(modbus)=%d", d, mode, before, after, len(resets), next, decodedProtocolEvents(e, "modbus"))
			if mode != "monitor" || before != sessionEstablished || after != sessionEstablished || len(resets) != 0 || decodedProtocolEvents(e, p.protocol) < 2 {
				t.Errorf("identical policy publication aborted the passive session; resets=%v; reply now %+v", resets, next)
			}

		})
	}
}

func TestPassivePickupSYNPanics(t *testing.T) {
	for _, closed := range []bool{false, true} {
		name := "live"
		if closed {
			name = "closed"
		}
		t.Run(name, func(t *testing.T) {
			p := runtimePairCases()[0]
			snap := rules.Snapshot{Default: rules.ActionAllow, DPIMode: "monitor", Firewall: []rules.Entry{runtimePairRule(p, "monitor")}}
			e := runtimePairEngine(t, snap, true)
			var panics []string
			e.onError = func(err error) { panics = append(panics, err.Error()) }
			passive := func(pkt capture.Packet) capture.Packet {
				pkt.HasMark, pkt.Mark, pkt.Queue = false, 0, nil // AF_PACKET has no nft marks
				return pkt
			}
			e.HandlePacket(passive(connSegment(true, 41000, p.port, 500, ackPsh, p.reply)))
			e.sessions.mu.Lock()
			n := len(e.sessions.sessions)
			e.sessions.mu.Unlock()
			if closed {
				rst := passive(connSegment(true, 41000, p.port, 500+uint32(len(p.reply)), capture.TCPFlagRST, nil))
				e.HandlePacket(rst)
			}
			syn := passive(connSegment(false, 41000, p.port, 9000, capture.TCPFlagSYN, nil))
			d := e.HandlePacket(syn)
			t.Logf("sessions=%d SYN decision=%+v panics=%v", n, d, panics)
			if len(panics) != 0 {
				t.Errorf("client SYN on a server-side pickup panicked the packet handler: %v", panics)
			}
		})
	}
}
