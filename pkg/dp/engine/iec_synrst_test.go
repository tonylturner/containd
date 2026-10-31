// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 containd Authors

package engine

import (
	"context"
	"testing"
	"time"

	"github.com/tonylturner/containd/pkg/dp/capture"
)

const synRSTFlags = capture.TCPFlagSYN | capture.TCPFlagRST

// TestIECSYNACKWithRSTDrops sends a SYN-ACK that also carries RST, which
// resets the client instead of completing its handshake: it drops and
// neither the incarnation nor the tombstone's next incarnation is
// established. The real SYN-ACK still establishes it.
func TestIECSYNACKWithRSTDrops(t *testing.T) {
	const synAckRST = capture.TCPFlagSYN | capture.TCPFlagACK | capture.TCPFlagRST
	h := newIECHarness(t, "enforce")
	if d := h.e.handlePacket(h.pkt(true, capture.TCPFlagSYN, 100, 0, nil)); d.Action != h.passingDisposition() {
		t.Fatalf("SYN = %+v, want Accept", d)
	}
	if d := h.e.handlePacket(h.pkt(false, synAckRST, 9000, 101, nil)); d.Action != h.deniedDisposition() || d.Reason != reasonIECInvalid {
		t.Fatalf("SYN-ACK with RST = %+v, want Drop by %s", d, reasonIECInvalid)
	}
	if st, _ := h.sessionState(); st != iecSynSent {
		t.Fatalf("session state %d, want awaiting its SYN-ACK", st)
	}
	if d := h.e.handlePacket(h.pkt(false, capture.TCPFlagSYN|capture.TCPFlagACK, 9000, 101, nil)); d.Action != h.passingDisposition() {
		t.Fatalf("SYN-ACK = %+v, want Accept", d)
	}
	if d := h.e.handlePacket(h.pkt(false, synAckRST, 9000, 101, nil)); d.Action != h.deniedDisposition() || d.Reason != reasonIECInvalid {
		t.Fatalf("retransmitted SYN-ACK with RST = %+v, want Drop by %s", d, reasonIECInvalid)
	}
	if st, _ := h.sessionState(); st != iecEstablished {
		t.Fatalf("session state %d, want established", st)
	}

	h = newIECHarness(t, "enforce")
	if d := h.e.handlePacket(h.pkt(false, capture.TCPFlagACK, 2000, 1000, nil)); d.Action != capture.Drop || d.Reason != reasonIECAbort {
		t.Fatalf("packet not observed from its SYN = %+v, want Drop by %s", d, reasonIECAbort)
	}
	if d := h.e.handlePacket(h.pkt(true, capture.TCPFlagSYN, 777, 0, nil)); d.Action != h.passingDisposition() {
		t.Fatalf("SYN on the tombstone = %+v, want Accept", d)
	}
	if d := h.e.handlePacket(h.pkt(false, synAckRST, 9000, 778, nil)); d.Action != h.deniedDisposition() || d.Reason != reasonIECInvalid {
		t.Fatalf("SYN-ACK with RST on the tombstone = %+v, want Drop by %s", d, reasonIECInvalid)
	}
	if st, _ := h.sessionState(); st != iecAborted {
		t.Fatalf("session state %d, want the tombstone", st)
	}
	if d := h.e.handlePacket(h.pkt(false, capture.TCPFlagSYN|capture.TCPFlagACK, 9000, 778, nil)); d.Action != h.passingDisposition() {
		t.Fatalf("SYN-ACK on the tombstone = %+v, want Accept", d)
	}
	if st, _ := h.sessionState(); st != iecEstablished {
		t.Fatalf("session state %d, want established", st)
	}
}

// TestIECSYNWithRSTOpensNothing sends a client SYN that also carries RST
// to 2404 with no session: it opens none. Learn passes it untracked;
// enforce drops it without aborting or resetting anything. The real SYN
// still opens the session, and a SYN with RST sent into it drops.
func TestIECSYNWithRSTOpensNothing(t *testing.T) {
	for _, tc := range []struct {
		mode   string
		action capture.Disposition
		reason string
	}{
		{"monitor", capture.Repeat, reasonIECAccept},
		{"enforce", capture.Drop, reasonIECInvalid},
	} {
		t.Run(tc.mode, func(t *testing.T) {
			h := newIECHarness(t, tc.mode)
			if d := h.e.handlePacket(h.pkt(true, synRSTFlags, 100, 0, nil)); d.Action != tc.action || d.Reason != tc.reason {
				t.Fatalf("SYN with RST = %+v, want %v by %s", d, tc.action, tc.reason)
			}
			if st, ok := h.sessionState(); ok {
				t.Fatalf("SYN with RST opened a session in state %d", st)
			}
			if len(h.inj.Resets()) != 0 {
				t.Fatalf("resets %+v, want none", h.inj.Resets())
			}
			h.handshake()
			if d := h.e.handlePacket(h.pkt(true, synRSTFlags, h.clientISN+5000, 0, nil)); d.Action != h.deniedDisposition() || d.Reason != reasonIECInvalid {
				t.Fatalf("SYN with RST into the session = %+v, want Drop by %s", d, reasonIECInvalid)
			}
			if st, _ := h.sessionState(); st != iecEstablished {
				t.Fatalf("session state %d, want established", st)
			}
			if _, d := h.send(true, iframe(46, 1)); d.Action != h.passingDisposition() {
				t.Fatalf("command = %+v, want Accept", d)
			}
			if evs := h.eventsOf("request"); len(evs) != 1 {
				t.Fatalf("requests %+v, want the command framed", evs)
			}
		})
	}
}

// TestIECSYNWithRSTOnClosedOpensNothing sends a client SYN with RST and a
// new ISN on a closed session: it drops and opens no next incarnation;
// the client's real SYN does.
func TestIECSYNWithRSTOnClosedOpensNothing(t *testing.T) {
	for _, mode := range []string{"enforce", "monitor"} {
		t.Run(mode, func(t *testing.T) {
			h := newIECHarness(t, mode)
			if d := h.e.handlePacket(h.pkt(true, capture.TCPFlagSYN, 100, 0, nil)); d.Action != h.passingDisposition() {
				t.Fatalf("SYN = %+v, want Accept", d)
			}
			if d := h.e.handlePacket(h.pkt(false, rstAck, 0, 101, nil)); d.Action != h.passingDisposition() || d.Reason != reasonIECClosed {
				t.Fatalf("refusing RST = %+v, want Accept by %s", d, reasonIECClosed)
			}
			if d := h.e.handlePacket(h.pkt(true, synRSTFlags, 700, 0, nil)); d.Action != h.deniedDisposition() || d.Reason != reasonIECInvalid {
				t.Fatalf("SYN with RST on the closed session = %+v, want Drop by %s", d, reasonIECInvalid)
			}
			if st, _ := h.sessionState(); st != iecClosed {
				t.Fatalf("session state %d, want closed", st)
			}
			if d := h.e.handlePacket(h.pkt(true, capture.TCPFlagSYN, 700, 0, nil)); d.Action != h.passingDisposition() || d.Reason != reasonIECAccept {
				t.Fatalf("next SYN = %+v, want Accept by %s", d, reasonIECAccept)
			}
			if st, _ := h.sessionState(); st != iecSynSent {
				t.Fatalf("session state %d, want awaiting its SYN-ACK", st)
			}
		})
	}
}

// TestIECSYNWithRSTOnTombstoneOpensNothing sends a client SYN with RST and
// a new ISN on a tombstone: it drops, answers no challenge and starts no
// next incarnation; the client's real SYN does.
func TestIECSYNWithRSTOnTombstoneOpensNothing(t *testing.T) {
	h := newIECHarness(t, "enforce")
	mid := h.pkt(false, capture.TCPFlagACK, 2000, 1000, nil)
	if d := h.e.handlePacket(mid); d.Action != capture.Drop || d.Reason != reasonIECAbort {
		t.Fatalf("packet not observed from its SYN = %+v, want Drop by %s", d, reasonIECAbort)
	}
	h.e.hooks.onVerdict(mid.Token, capture.VerdictDrop, nil)
	resets := len(h.waitResets(2))
	if d := h.e.handlePacket(h.pkt(true, synRSTFlags, 777, 0, nil)); d.Action != h.deniedDisposition() || d.Reason != reasonIECInvalid {
		t.Fatalf("SYN with RST on the tombstone = %+v, want Drop by %s", d, reasonIECInvalid)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if !h.e.hooks.blocks.flush(ctx.Done()) {
		t.Fatal("reset worker did not reach its barrier")
	}
	if got := len(h.inj.Resets()); got != resets {
		t.Fatalf("resets %d, want %d: the SYN with RST answers no challenge", got, resets)
	}
	if d := h.e.handlePacket(h.pkt(false, capture.TCPFlagSYN|capture.TCPFlagACK, 9000, 778, nil)); d.Action != capture.Drop || d.Reason != reasonIECTombstone {
		t.Fatalf("SYN-ACK answering the SYN with RST = %+v, want Drop by %s", d, reasonIECTombstone)
	}
	if st, _ := h.sessionState(); st != iecAborted {
		t.Fatalf("session state %d, want the tombstone", st)
	}
	if d := h.e.handlePacket(h.pkt(true, capture.TCPFlagSYN, 777, 0, nil)); d.Action != h.passingDisposition() {
		t.Fatalf("SYN on the tombstone = %+v, want Accept", d)
	}
	if d := h.e.handlePacket(h.pkt(false, capture.TCPFlagSYN|capture.TCPFlagACK, 9000, 778, nil)); d.Action != h.passingDisposition() {
		t.Fatalf("SYN-ACK on the tombstone = %+v, want Accept", d)
	}
	if st, _ := h.sessionState(); st != iecEstablished {
		t.Fatalf("session state %d, want established", st)
	}
}
