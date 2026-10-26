// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 containd Authors

package engine

import (
	"testing"

	"github.com/tonylturner/containd/pkg/dp/capture"
)

// TestIECRSTClosesOnlyAtReceivePoint sends bare RSTs into an established
// incarnation: one at the sequence number the receiver expects next closes
// it, after dropping its held packets; one inside the bytes still in
// flight to the receiver, or out of window, passes without closing it, and
// the incarnation keeps inspecting.
func TestIECRSTClosesOnlyAtReceivePoint(t *testing.T) {
	for _, tc := range []struct {
		name       string
		fromClient bool
		seq        func(h *iecHarness) uint32
		closes     bool
	}{
		{"client RST at the server's receive point", true, func(h *iecHarness) uint32 { return h.cSeq }, true},
		{"server RST at the client's receive point", false, func(h *iecHarness) uint32 { return h.sSeq }, true},
		{"client RST inside the bytes in flight", true, func(h *iecHarness) uint32 { return h.cSeq - 8 }, false},
		{"client RST ahead of the stream", true, func(h *iecHarness) uint32 { return h.cSeq + 4096 }, false},
		{"client RST out of window", true, func(h *iecHarness) uint32 { return h.cSeq + 1<<31 }, false},
		{"server RST behind the stream", false, func(h *iecHarness) uint32 { return h.sSeq - 1000 }, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := newIECHarness(t, "enforce")
			h.handshake()
			h.send(true, iframe(46, 1))
			h.send(false, startdtCon)
			d := h.e.handlePacket(h.pkt(tc.fromClient, capture.TCPFlagRST, tc.seq(h), 0, nil))
			if d.Action != capture.Accept {
				t.Fatalf("RST = %+v, want Accept", d)
			}
			st, _ := h.sessionState()
			if closed := st == iecClosed; closed != tc.closes {
				t.Fatalf("session state %d after the RST, want closed %v", st, tc.closes)
			}
			if tc.closes {
				return
			}
			if _, d := h.send(true, iframe(46, 2)); d.Action != capture.Accept {
				t.Fatalf("command after the RST = %+v, want Accept", d)
			}
			if _, d := h.send(true, iframe(45, 3)); d.Action != capture.Drop || d.Reason != reasonIECAbort {
				t.Fatalf("denied command after the RST = %+v, want Drop by %s", d, reasonIECAbort)
			}
		})
	}
}

// TestIECRSTAtReceivePointDropsHeld closes an incarnation that holds a
// partial command at a RST that precedes the held bytes, and drops them.
func TestIECRSTAtReceivePointDropsHeld(t *testing.T) {
	h := newIECHarness(t, "enforce")
	h.handshake()
	at := h.cSeq
	held, d := h.send(true, iframe(46, 1)[:4])
	if d.Action != capture.Hold {
		t.Fatalf("partial command = %+v, want Hold", d)
	}
	if d := h.e.handlePacket(h.pkt(true, capture.TCPFlagRST, h.cSeq, 0, nil)); d.Action != capture.Accept {
		t.Fatalf("RST after the held bytes = %+v, want Accept", d)
	}
	if st, _ := h.sessionState(); st != iecEstablished {
		t.Fatalf("session state %d after a RST past the receive point, want established", st)
	}
	d = h.e.handlePacket(h.pkt(true, capture.TCPFlagRST, at, 0, nil))
	if d.Action != capture.Accept || len(d.Resolved) != 1 || d.Resolved[0].Token != held.Token || d.Resolved[0].Verdict != capture.VerdictDrop {
		t.Fatalf("RST at the receive point = %+v, want Accept dropping the held packet", d)
	}
	if st, _ := h.sessionState(); st != iecClosed {
		t.Fatalf("session state %d, want closed", st)
	}
}

// TestIECReconnectSamePortAfterLostConnection loses the client's side of
// an established incarnation, as a client that restarts without a RST
// does, and reconnects from the same port. Its SYN into the connection
// passes and opens nothing; the server's challenge ACK passes; the
// client's RST at it closes the incarnation; the client's next SYN, of a
// new handshake, opens the next incarnation, inspected from its first
// byte.
func TestIECReconnectSamePortAfterLostConnection(t *testing.T) {
	h := newIECHarness(t, "enforce")
	h.handshake()
	h.send(true, iframe(46, 1))
	h.send(false, startdtCon)
	if d := h.e.handlePacket(h.establishedSYN(777, nil)); d.Action != capture.Accept || d.Reason != reasonIECEstablishedSYN {
		t.Fatalf("SYN into the connection = %+v, want Accept by %s", d, reasonIECEstablishedSYN)
	}
	if d := h.e.handlePacket(h.establishedSYN(777, iframe(46, 2))); d.Action != capture.Drop || d.Reason != reasonIECInvalid {
		t.Fatalf("SYN with data into the connection = %+v, want Drop by %s", d, reasonIECInvalid)
	}
	if st, _ := h.sessionState(); st != iecEstablished {
		t.Fatalf("session state %d after the SYNs, want established", st)
	}
	if d := h.e.handlePacket(h.pkt(false, capture.TCPFlagACK, h.sSeq, h.cSeq, nil)); d.Action != capture.Accept {
		t.Fatalf("challenge ACK = %+v, want Accept", d)
	}
	if d := h.e.handlePacket(h.pkt(true, capture.TCPFlagRST, h.cSeq, 0, nil)); d.Action != capture.Accept {
		t.Fatalf("client RST at the challenge ACK = %+v, want Accept", d)
	}
	if st, _ := h.sessionState(); st != iecClosed {
		t.Fatalf("session state %d after the RST, want closed", st)
	}
	if d := h.e.handlePacket(h.pkt(true, capture.TCPFlagSYN, 777, 0, nil)); d.Action != capture.Accept {
		t.Fatalf("handshake SYN = %+v, want Accept", d)
	}
	if d := h.e.handlePacket(h.pkt(false, capture.TCPFlagSYN|capture.TCPFlagACK, 9000, 778, nil)); d.Action != capture.Accept {
		t.Fatalf("SYN-ACK = %+v, want Accept", d)
	}
	h.cSeq, h.sSeq = 778, 9001
	if _, d := h.send(true, iframe(46, 3)); d.Action != capture.Accept {
		t.Fatalf("command on the next incarnation = %+v, want Accept", d)
	}
	if _, d := h.send(true, iframe(45, 4)); d.Action != capture.Drop || d.Reason != reasonIECAbort {
		t.Fatalf("denied command on the next incarnation = %+v, want Drop by %s", d, reasonIECAbort)
	}
}

// TestIECHandshakeSYNReopensEstablished sends the SYN of a new handshake
// into an established incarnation, as after connection tracking forgot
// the connection. An enforce incarnation aborts, resetting both endpoints,
// and the client's retransmitted SYN opens the next incarnation; a learn
// incarnation closes and the SYN opens the next one at once.
func TestIECHandshakeSYNReopensEstablished(t *testing.T) {
	t.Run("enforce", func(t *testing.T) {
		h := newIECHarness(t, "enforce")
		h.handshake()
		h.send(true, iframe(46, 1))
		syn := h.pkt(true, capture.TCPFlagSYN, 777, 0, nil)
		if d := h.e.handlePacket(syn); d.Action != capture.Drop || d.Reason != reasonIECAbort {
			t.Fatalf("handshake SYN into the incarnation = %+v, want Drop by %s", d, reasonIECAbort)
		}
		h.e.hooks.onVerdict(syn.Token, capture.VerdictDrop, nil)
		h.waitResets(2)
		if d := h.e.handlePacket(h.pkt(true, capture.TCPFlagSYN, 777, 0, nil)); d.Action != capture.Accept {
			t.Fatalf("retransmitted SYN = %+v, want Accept", d)
		}
		if d := h.e.handlePacket(h.pkt(false, capture.TCPFlagSYN|capture.TCPFlagACK, 9000, 778, nil)); d.Action != capture.Accept {
			t.Fatalf("SYN-ACK = %+v, want Accept", d)
		}
		h.cSeq, h.sSeq = 778, 9001
		if _, d := h.send(true, iframe(46, 2)); d.Action != capture.Accept {
			t.Fatalf("command on the next incarnation = %+v, want Accept", d)
		}
	})
	t.Run("learn", func(t *testing.T) {
		h := newIECHarness(t, "learn")
		h.handshake()
		if d := h.e.handlePacket(h.pkt(true, capture.TCPFlagSYN, 777, 0, nil)); d.Action != capture.Accept {
			t.Fatalf("handshake SYN into the learn incarnation = %+v, want Accept", d)
		}
		if st, _ := h.sessionState(); st != iecSynSent {
			t.Fatalf("session state %d, want the next incarnation opened", st)
		}
	})
}
