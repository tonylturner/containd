// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 containd Authors

package engine

import (
	"net/netip"
	"reflect"
	"testing"

	"github.com/tonylturner/containd/pkg/dp/capture"
	"github.com/tonylturner/containd/pkg/dp/session"
)

// establishedSYN is a client SYN sent into an established connection: nft
// queues it without the handshake mark.
func (h *iecHarness) establishedSYN(isn uint32, payload []byte) capture.Packet {
	p := h.pkt(true, capture.TCPFlagSYN, isn, 0, payload)
	p.HasMark, p.Mark = false, 0
	return p
}

func (h *iecHarness) sessionState() (iecState, bool) {
	h.e.iec.mu.Lock()
	defer h.e.iec.mu.Unlock()
	s := h.e.iec.sessions[iecKey{client: netip.MustParseAddrPort("10.60.60.10:40000"), server: netip.MustParseAddrPort("10.30.30.30:2404")}]
	if s == nil {
		return 0, false
	}
	return s.state, true
}

// TestIECEstablishedSYNOpensNothing sends, after an engine restart, a SYN
// into the established connection whose sequence number would start a
// session at the client's next byte. It opens no session: without payload
// it passes, and the server's challenge ACK, not observed from a SYN,
// closes the connection at both endpoints. The client's next bytes are
// never framed, and its handshake opens the next incarnation.
func TestIECEstablishedSYNOpensNothing(t *testing.T) {
	h := newIECHarness(t, "enforce")
	if d := h.e.handlePacket(h.establishedSYN(999, iframe(46, 1))); d.Action != capture.Drop || d.Reason != reasonIECInvalid {
		t.Fatalf("SYN with data = %+v, want Drop by %s", d, reasonIECInvalid)
	}
	if d := h.e.handlePacket(h.establishedSYN(999, nil)); d.Action != h.passingDisposition() || d.Reason != reasonIECEstablishedSYN {
		t.Fatalf("SYN into the connection = %+v, want Accept by %s", d, reasonIECEstablishedSYN)
	}
	if _, ok := h.sessionState(); ok {
		t.Fatal("the SYN opened a session")
	}
	ack := h.pkt(false, capture.TCPFlagACK, 2000, 1000, nil)
	if d := h.e.handlePacket(ack); d.Action != capture.Drop || d.Reason != reasonIECAbort {
		t.Fatalf("challenge ACK = %+v, want Drop by %s", d, reasonIECAbort)
	}
	h.e.hooks.onVerdict(ack.Token, capture.VerdictDrop, nil)
	client := netip.MustParseAddrPort("10.60.60.10:40000")
	server := netip.MustParseAddrPort("10.30.30.30:2404")
	want := []session.Reset{{Src: client, Dst: server, Seq: 1000}, {Src: server, Dst: client, Seq: 2000}}
	if got := h.waitResets(2); !reflect.DeepEqual(got, want) {
		t.Fatalf("resets = %+v, want %+v", got, want)
	}
	if _, d := h.send(true, iframe(46, 1)); d.Action != capture.Drop {
		t.Fatalf("client data after the SYN = %+v, want Drop", d)
	}
	if evs := h.eventsOf("request"); len(evs) != 0 {
		t.Fatalf("client bytes framed after the SYN: %+v", evs)
	}
	if d := h.e.handlePacket(h.establishedSYN(777, nil)); d.Action != capture.Drop || d.Reason != reasonIECTombstone {
		t.Fatalf("SYN into the connection on the tombstone = %+v, want Drop by %s", d, reasonIECTombstone)
	}
	if d := h.e.handlePacket(h.pkt(true, capture.TCPFlagSYN, 777, 0, nil)); d.Action != h.passingDisposition() {
		t.Fatalf("handshake SYN = %+v, want Accept", d)
	}
	if d := h.e.handlePacket(h.pkt(false, capture.TCPFlagSYN|capture.TCPFlagACK, 9000, 778, nil)); d.Action != h.passingDisposition() {
		t.Fatalf("SYN-ACK = %+v, want Accept", d)
	}
	h.cSeq, h.sSeq = 778, 9001
	if _, d := h.send(true, iframe(46, 1)); d.Action != h.passingDisposition() {
		t.Fatalf("command on the next incarnation = %+v, want Accept", d)
	}
	if evs := h.eventsOf("request"); len(evs) != 1 {
		t.Fatalf("requests %+v, want the next incarnation's command framed", evs)
	}
}

// TestIECEstablishedSYNOnSessionStates covers the other states a SYN sent
// into an established connection can meet: a closed session passes it as
// its payload-free tail and stays closed, a session awaiting its SYN-ACK
// keeps its ISN, and a learn envelope opens a session at it as before.
func TestIECEstablishedSYNOnSessionStates(t *testing.T) {
	h := newIECHarness(t, "enforce")
	h.handshake()
	if d := h.e.handlePacket(h.pkt(true, capture.TCPFlagRST, h.cSeq, 0, nil)); d.Action != h.passingDisposition() {
		t.Fatalf("client RST = %+v, want Accept", d)
	}
	if d := h.e.handlePacket(h.establishedSYN(777, nil)); d.Action != h.passingDisposition() || d.Reason != reasonIECClosed {
		t.Fatalf("SYN into the connection on the closed session = %+v, want Accept by %s", d, reasonIECClosed)
	}
	if st, _ := h.sessionState(); st != iecClosed {
		t.Fatalf("session state %d, want closed", st)
	}

	h = newIECHarness(t, "enforce")
	if d := h.e.handlePacket(h.pkt(true, capture.TCPFlagSYN, 100, 0, nil)); d.Action != h.passingDisposition() {
		t.Fatalf("handshake SYN = %+v, want Accept", d)
	}
	if d := h.e.handlePacket(h.establishedSYN(500, nil)); d.Action != capture.Drop || d.Reason != reasonIECInvalid {
		t.Fatalf("SYN with a new ISN into the connection = %+v, want Drop by %s", d, reasonIECInvalid)
	}
	if d := h.e.handlePacket(h.pkt(false, capture.TCPFlagSYN|capture.TCPFlagACK, 9000, 101, nil)); d.Action != h.passingDisposition() {
		t.Fatalf("SYN-ACK of the first SYN = %+v, want Accept", d)
	}

	h = newIECHarness(t, "monitor")
	if d := h.e.handlePacket(h.establishedSYN(100, nil)); d.Action != h.passingDisposition() || d.Reason != reasonIECAccept {
		t.Fatalf("learn SYN = %+v, want Accept by %s", d, reasonIECAccept)
	}
	if st, ok := h.sessionState(); !ok || st != iecSynSent {
		t.Fatalf("learn session state %d (%v), want opened", st, ok)
	}
}
