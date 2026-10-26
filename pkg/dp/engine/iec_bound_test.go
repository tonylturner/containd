// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 containd Authors

package engine

import (
	"testing"
	"time"

	"github.com/tonylturner/containd/pkg/dp/capture"
)

func TestIECSessionTrackingBound(t *testing.T) {
	for _, mode := range []string{"learn", "enforce"} {
		t.Run(mode, func(t *testing.T) {
			h := newIECHarness(t, mode)
			h.handshake()
			trackedPort := h.cport
			// Real distinct-tuple SYNs exercise allocation, not a prefilled map.
			for i := 1; i < iecMaxSessions; i++ {
				h.cport = trackedPort + uint16(i)
				if d := h.e.handlePacket(h.pkt(true, capture.TCPFlagSYN, testClientISN, 0, nil)); d.Action != capture.Accept {
					t.Fatalf("SYN %d = %+v", i, d)
				}
			}
			table := h.e.iec
			if len(table.sessions) != iecMaxSessions {
				t.Fatalf("tracked = %d, want %d", len(table.sessions), iecMaxSessions)
			}
			table.newID = func() string {
				t.Fatal("allocated an incarnation beyond the tracking bound")
				return ""
			}
			h.cport = trackedPort + iecMaxSessions
			wantAction, wantReason := capture.Drop, reasonIECFailClose
			if mode == "learn" {
				wantAction, wantReason = capture.Accept, reasonIECUntracked
			}
			for i := 0; i < 3; i++ {
				h.cport++
				p := h.pkt(true, capture.TCPFlagSYN, 777, 0, nil)
				if d := h.e.handlePacket(p); d.Action != wantAction || d.Reason != wantReason {
					t.Fatalf("overflow SYN = %+v, want %v/%s", d, wantAction, wantReason)
				}
				// The same untracked connection must remain fail open in
				// learn and fail closed in enforce, even after its handshake.
				for _, p := range []capture.Packet{
					h.pkt(false, capture.TCPFlagSYN|capture.TCPFlagACK, 9000, 778, nil),
					h.pkt(true, capture.TCPFlagACK|capture.TCPFlagPSH, 778, 9001, iframe(45, 1)),
					h.pkt(false, capture.TCPFlagFIN|capture.TCPFlagACK, 9001, 794, nil),
				} {
					if d := h.e.handlePacket(p); d.Action != wantAction {
						t.Fatalf("untracked packet = %+v, want %v", d, wantAction)
					}
				}
			}
			if len(table.sessions) != iecMaxSessions || len(h.inj.Resets()) != 0 || table.heldTotal != 0 {
				t.Fatal("overflow traffic allocated sessions, held packets, or sent resets")
			}
			evs := h.eventsOf("ics.session")
			if mode == "learn" {
				if len(evs) != 3 {
					t.Fatalf("untracked events = %+v, want one per overflow SYN", evs)
				}
				for _, ev := range evs {
					if ev.Attributes["outcome"] != "untracked" || ev.Attributes["reason"] != "bound" ||
						ev.Attributes["mode"] != "learn" || ev.Attributes["limit"] != iecMaxSessions ||
						ev.SrcIP != h.client.String() || ev.DstIP != h.server.String() || ev.DstPort != iec104Port {
						t.Fatalf("untracked evidence = %+v", ev)
					}
					if _, ok := ev.Attributes["session_id"]; ok {
						t.Fatal("untracked event claimed a session ID")
					}
				}
			} else if len(evs) != 0 {
				t.Fatalf("enforce overflow reported learn evidence: %+v", evs)
			}
			// Existing sessions keep their stream and policy at capacity.
			h.cport = trackedPort
			if _, d := h.send(true, iframe(46, 1)); d.Action != capture.Accept {
				t.Fatalf("tracked allowed APDU at capacity = %+v", d)
			}
			// Expiry restores tracking; unobserved midstream packets do not
			// allocate a learn session before the next SYN.
			h.clock = h.clock.Add(iecIdleTTL + time.Second)
			table.expire()
			if len(table.sessions) != 0 {
				t.Fatalf("expired sessions retained: %d", len(table.sessions))
			}
			table.newID = nextLiveSessionID
			h.cport++
			h.handshake()
			if len(table.sessions) != 1 {
				t.Fatalf("tracking did not recover: %d", len(table.sessions))
			}
		})
	}
}

func TestIECSessionTrackingBoundTupleReuse(t *testing.T) {
	for _, tc := range []struct {
		name    string
		oldMode string
		mode    string
		aborted bool
	}{
		{"aborted/enforce", "enforce", "enforce", true},
		{"aborted/enforce_to_learn", "enforce", "learn", true},
		{"closed/learn", "learn", "learn", false},
		{"closed/enforce", "enforce", "enforce", false},
		{"closed/enforce_to_learn", "enforce", "learn", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := newIECHarness(t, tc.oldMode)
			h.handshake()
			trackedPort := h.cport
			table := h.e.iec
			client, _ := addrPort(h.client, h.cport)
			server, _ := addrPort(h.server, iec104Port)
			key := iecKey{client: client, server: server}
			prev := table.sessions[key]
			wantState := iecClosed
			if tc.aborted {
				p, d := h.send(true, iframe(45, 1))
				if d.Action != capture.Drop || d.Reason != reasonIECAbort {
					t.Fatalf("abort = %+v", d)
				}
				h.e.hooks.onVerdict(p.Token, capture.VerdictDrop, nil)
				h.waitResets(2)
				wantState = iecAborted
			} else if d := h.e.handlePacket(h.pkt(true, capture.TCPFlagRST|capture.TCPFlagACK, h.cSeq, h.sSeq, nil)); d.Action != capture.Accept {
				t.Fatalf("close = %+v", d)
			}
			if prev.state != wantState || table.sessions[key] != prev {
				t.Fatalf("retained session = %+v, want state %v", prev, wantState)
			}
			// Retained sessions keep their original mode across a policy
			// change; their next incarnation must use the current envelope.
			if tc.mode != tc.oldMode {
				h.policy.mode = tc.mode
				h.e.LoadRules(iecSnapshot(tc.mode))
			}
			for i := 1; i < iecMaxSessions; i++ {
				h.cport = trackedPort + uint16(i)
				if d := h.e.handlePacket(h.pkt(true, capture.TCPFlagSYN, testClientISN, 0, nil)); d.Action != capture.Accept {
					t.Fatalf("filling SYN %d = %+v", i, d)
				}
			}
			handle := func(p capture.Packet) capture.Decision {
				t.Helper()
				d := h.e.handlePacket(p)
				if len(table.sessions) != iecMaxSessions {
					t.Fatalf("tracked = %d, want %d", len(table.sessions), iecMaxSessions)
				}
				return d
			}
			h.cport = trackedPort
			if d := handle(h.pkt(true, capture.TCPFlagSYN, 777, 0, nil)); d.Action != capture.Accept || d.Reason != reasonIECAccept {
				t.Fatalf("reuse SYN = %+v", d)
			}
			n := table.sessions[key]
			if tc.aborted {
				n = prev.next
				if table.sessions[key] != prev {
					t.Fatal("tombstone retired before the new handshake validated")
				}
				for _, p := range []capture.Packet{
					h.pkt(true, capture.TCPFlagSYN, testClientISN, 0, nil),
					h.pkt(false, capture.TCPFlagSYN|capture.TCPFlagACK, testServerISN, testClientISN+1, nil),
				} {
					if d := handle(p); d.Action != capture.Drop || d.Reason != reasonIECTombstone {
						t.Fatalf("old incarnation packet = %+v", d)
					}
				}
			}
			if n == nil || n == prev || n.id == prev.id || n.mode != tc.mode || n.state != iecSynSent || n.dirs[iecDirClient].isn != 777 {
				t.Fatalf("new tracked incarnation = %+v", n)
			}
			for _, p := range []capture.Packet{
				h.pkt(false, capture.TCPFlagSYN|capture.TCPFlagACK, 9000, 778, nil),
				h.pkt(true, capture.TCPFlagACK, 778, 9001, nil),
				h.pkt(true, capture.TCPFlagACK|capture.TCPFlagPSH, 778, 9001, iframe(46, 1)),
			} {
				if d := handle(p); d.Action != capture.Accept || d.Reason != reasonIECAccept {
					t.Fatalf("new incarnation packet %+v = %+v", p.TCP, d)
				}
			}
			if table.sessions[key] != n || n.state != iecEstablished || n.dirs[iecDirSrv].isn != 9000 || table.tombstones != 0 {
				t.Fatal("new handshake did not replace the retained incarnation")
			}
			// Only a new tuple consumes another key and must hit the cap.
			h.cport = trackedPort + iecMaxSessions
			wantAction, wantReason := capture.Drop, reasonIECFailClose
			if tc.mode == "learn" {
				wantAction, wantReason = capture.Accept, reasonIECUntracked
			}
			if d := handle(h.pkt(true, capture.TCPFlagSYN, 777, 0, nil)); d.Action != wantAction || d.Reason != wantReason {
				t.Fatalf("new tuple SYN = %+v, want %v/%s", d, wantAction, wantReason)
			}
		})
	}
}
