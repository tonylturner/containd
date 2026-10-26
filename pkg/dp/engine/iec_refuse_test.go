// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 containd Authors

package engine

import (
	"testing"

	"github.com/tonylturner/containd/pkg/dp/capture"
)

const rstAck = capture.TCPFlagRST | capture.TCPFlagACK

// TestIECRefusingRSTCloses sends the server's RST refusing the client's
// SYN, as a station with no listener on 2404 answers it. It reaches the
// client, which fails at once, and closes the incarnation; the client's
// next SYN from the same port opens the next one, inspected from its
// first byte.
func TestIECRefusingRSTCloses(t *testing.T) {
	for _, mode := range []string{"enforce", "learn"} {
		t.Run(mode, func(t *testing.T) {
			h := newIECHarness(t, mode)
			if d := h.e.handlePacket(h.pkt(true, capture.TCPFlagSYN, 100, 0, nil)); d.Action != capture.Accept {
				t.Fatalf("SYN = %+v, want Accept", d)
			}
			if d := h.e.handlePacket(h.pkt(false, rstAck, 0, 101, nil)); d.Action != capture.Accept || d.Reason != reasonIECClosed {
				t.Fatalf("refusing RST = %+v, want Accept by %s", d, reasonIECClosed)
			}
			if st, _ := h.sessionState(); st != iecClosed {
				t.Fatalf("session state %d, want closed", st)
			}
			if len(h.inj.Resets()) != 0 {
				t.Fatalf("resets %+v, want none", h.inj.Resets())
			}
			if d := h.e.handlePacket(h.pkt(true, capture.TCPFlagSYN, 700, 0, nil)); d.Action != capture.Accept || d.Reason != reasonIECAccept {
				t.Fatalf("next SYN = %+v, want Accept by %s", d, reasonIECAccept)
			}
			if d := h.e.handlePacket(h.pkt(false, capture.TCPFlagSYN|capture.TCPFlagACK, 9000, 701, nil)); d.Action != capture.Accept {
				t.Fatalf("next SYN-ACK = %+v, want Accept", d)
			}
			h.cSeq, h.sSeq = 701, 9001
			if _, d := h.send(true, iframe(46, 1)); d.Action != capture.Accept {
				t.Fatalf("command on the next incarnation = %+v, want Accept", d)
			}
			if evs := h.eventsOf("request"); len(evs) != 1 {
				t.Fatalf("requests %+v, want the next incarnation's command framed", evs)
			}
		})
	}
}

// TestIECOtherPacketsBeforeSYNACKDrop sends, in an enforce envelope, every
// packet before the SYN-ACK that does not refuse the client's current SYN:
// they drop, the incarnation stays open, and its SYN-ACK still passes.
func TestIECOtherPacketsBeforeSYNACKDrop(t *testing.T) {
	h := newIECHarness(t, "enforce")
	if d := h.e.handlePacket(h.pkt(true, capture.TCPFlagSYN, 100, 0, nil)); d.Action != capture.Accept {
		t.Fatalf("SYN = %+v, want Accept", d)
	}
	if d := h.e.handlePacket(h.pkt(true, capture.TCPFlagSYN, 200, 0, nil)); d.Action != capture.Accept {
		t.Fatalf("SYN with a new ISN = %+v, want Accept", d)
	}
	for _, tc := range []struct {
		name string
		pkt  capture.Packet
	}{
		{"RST with a wrong ACK", h.pkt(false, rstAck, 0, 202, nil)},
		{"RST acknowledging the previous SYN", h.pkt(false, rstAck, 0, 101, nil)},
		{"RST without ACK", h.pkt(false, capture.TCPFlagRST, 0, 201, nil)},
		{"RST with payload", h.pkt(false, rstAck, 0, 201, iframe(46, 1))},
		{"client RST", h.pkt(true, rstAck, 201, 201, nil)},
		{"server ACK", h.pkt(false, capture.TCPFlagACK, 0, 201, nil)},
		{"server data", h.pkt(false, capture.TCPFlagACK|capture.TCPFlagPSH, 0, 201, iframe(46, 1))},
		{"client data", h.pkt(true, capture.TCPFlagACK|capture.TCPFlagPSH, 201, 0, iframe(46, 1))},
	} {
		if d := h.e.handlePacket(tc.pkt); d.Action != capture.Drop || d.Reason != reasonIECInvalid {
			t.Fatalf("%s = %+v, want Drop by %s", tc.name, d, reasonIECInvalid)
		}
		if st, _ := h.sessionState(); st != iecSynSent {
			t.Fatalf("after %s: session state %d, want awaiting its SYN-ACK", tc.name, st)
		}
	}
	if d := h.e.handlePacket(h.pkt(false, capture.TCPFlagSYN|capture.TCPFlagACK, 9000, 201, nil)); d.Action != capture.Accept {
		t.Fatalf("SYN-ACK = %+v, want Accept", d)
	}
	if st, _ := h.sessionState(); st != iecEstablished {
		t.Fatalf("session state %d, want established", st)
	}
	if evs := h.eventsOf("request"); len(evs) != 0 {
		t.Fatalf("bytes framed before the SYN-ACK: %+v", evs)
	}
}

// TestIECRefusingRSTOnTombstone refuses the SYN of the incarnation that
// follows an aborted one: the RST passes, the tombstone keeps dropping the
// aborted incarnation's packets, and the client's next SYN opens another.
func TestIECRefusingRSTOnTombstone(t *testing.T) {
	h := newIECHarness(t, "enforce")
	if d := h.e.handlePacket(h.pkt(false, capture.TCPFlagACK, 2000, 1000, nil)); d.Action != capture.Drop || d.Reason != reasonIECAbort {
		t.Fatalf("packet not observed from its SYN = %+v, want Drop by %s", d, reasonIECAbort)
	}
	if d := h.e.handlePacket(h.pkt(true, capture.TCPFlagSYN, 777, 0, nil)); d.Action != capture.Accept {
		t.Fatalf("SYN on the tombstone = %+v, want Accept", d)
	}
	if d := h.e.handlePacket(h.pkt(false, rstAck, 0, 779, nil)); d.Action != capture.Drop || d.Reason != reasonIECTombstone {
		t.Fatalf("RST with a wrong ACK = %+v, want Drop by %s", d, reasonIECTombstone)
	}
	if d := h.e.handlePacket(h.pkt(false, rstAck, 0, 778, nil)); d.Action != capture.Accept || d.Reason != reasonIECClosed {
		t.Fatalf("refusing RST = %+v, want Accept by %s", d, reasonIECClosed)
	}
	if st, _ := h.sessionState(); st != iecAborted {
		t.Fatalf("session state %d, want the tombstone", st)
	}
	if d := h.e.handlePacket(h.pkt(false, capture.TCPFlagSYN|capture.TCPFlagACK, 9000, 778, nil)); d.Action != capture.Drop || d.Reason != reasonIECTombstone {
		t.Fatalf("SYN-ACK of the refused SYN = %+v, want Drop by %s", d, reasonIECTombstone)
	}
	if d := h.e.handlePacket(h.pkt(true, capture.TCPFlagSYN, 888, 0, nil)); d.Action != capture.Accept {
		t.Fatalf("next SYN = %+v, want Accept", d)
	}
	if d := h.e.handlePacket(h.pkt(false, capture.TCPFlagSYN|capture.TCPFlagACK, 9100, 889, nil)); d.Action != capture.Accept {
		t.Fatalf("next SYN-ACK = %+v, want Accept", d)
	}
	if st, _ := h.sessionState(); st != iecEstablished {
		t.Fatalf("session state %d, want established", st)
	}
}

// TestIECSYNACKWithRSTDrops sends a SYN-ACK that also carries RST, which
// resets the client instead of completing its handshake: it drops and
// neither the incarnation nor the tombstone's next incarnation is
// established. The real SYN-ACK still establishes it.
func TestIECSYNACKWithRSTDrops(t *testing.T) {
	const synAckRST = capture.TCPFlagSYN | capture.TCPFlagACK | capture.TCPFlagRST
	h := newIECHarness(t, "enforce")
	if d := h.e.handlePacket(h.pkt(true, capture.TCPFlagSYN, 100, 0, nil)); d.Action != capture.Accept {
		t.Fatalf("SYN = %+v, want Accept", d)
	}
	if d := h.e.handlePacket(h.pkt(false, synAckRST, 9000, 101, nil)); d.Action != capture.Drop || d.Reason != reasonIECInvalid {
		t.Fatalf("SYN-ACK with RST = %+v, want Drop by %s", d, reasonIECInvalid)
	}
	if st, _ := h.sessionState(); st != iecSynSent {
		t.Fatalf("session state %d, want awaiting its SYN-ACK", st)
	}
	if d := h.e.handlePacket(h.pkt(false, capture.TCPFlagSYN|capture.TCPFlagACK, 9000, 101, nil)); d.Action != capture.Accept {
		t.Fatalf("SYN-ACK = %+v, want Accept", d)
	}
	if d := h.e.handlePacket(h.pkt(false, synAckRST, 9000, 101, nil)); d.Action != capture.Drop || d.Reason != reasonIECInvalid {
		t.Fatalf("retransmitted SYN-ACK with RST = %+v, want Drop by %s", d, reasonIECInvalid)
	}
	if st, _ := h.sessionState(); st != iecEstablished {
		t.Fatalf("session state %d, want established", st)
	}

	h = newIECHarness(t, "enforce")
	if d := h.e.handlePacket(h.pkt(false, capture.TCPFlagACK, 2000, 1000, nil)); d.Action != capture.Drop || d.Reason != reasonIECAbort {
		t.Fatalf("packet not observed from its SYN = %+v, want Drop by %s", d, reasonIECAbort)
	}
	if d := h.e.handlePacket(h.pkt(true, capture.TCPFlagSYN, 777, 0, nil)); d.Action != capture.Accept {
		t.Fatalf("SYN on the tombstone = %+v, want Accept", d)
	}
	if d := h.e.handlePacket(h.pkt(false, synAckRST, 9000, 778, nil)); d.Action != capture.Drop || d.Reason != reasonIECInvalid {
		t.Fatalf("SYN-ACK with RST on the tombstone = %+v, want Drop by %s", d, reasonIECInvalid)
	}
	if st, _ := h.sessionState(); st != iecAborted {
		t.Fatalf("session state %d, want the tombstone", st)
	}
	if d := h.e.handlePacket(h.pkt(false, capture.TCPFlagSYN|capture.TCPFlagACK, 9000, 778, nil)); d.Action != capture.Accept {
		t.Fatalf("SYN-ACK on the tombstone = %+v, want Accept", d)
	}
	if st, _ := h.sessionState(); st != iecEstablished {
		t.Fatalf("session state %d, want established", st)
	}
}
