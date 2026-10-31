// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

package engine

import (
	"net/netip"
	"reflect"
	"testing"

	"github.com/tonylturner/containd/pkg/dp/capture"
	"github.com/tonylturner/containd/pkg/dp/markabi"
	"github.com/tonylturner/containd/pkg/dp/session"
)

// Golden RST targets: for target X the sequence is the
// end of the last byte forwarded to X, whichever side sent the denied APDU.

var (
	goldenClient = netip.MustParseAddrPort("10.60.60.10:40000")
	goldenServer = netip.MustParseAddrPort("10.30.30.30:2404")
)

func abortAndResets(t *testing.T, h *iecHarness, cur capture.Packet) []session.Reset {
	t.Helper()
	h.e.hooks.onVerdict(cur.Token, capture.VerdictDrop, nil)
	return h.waitResets(2)
}

func TestIECResetGoldenServerSideDenial(t *testing.T) {
	h := newIECHarness(t, "enforce")
	h.handshake()
	h.send(true, iframe(46, 1))  // 16 bytes forwarded to the server
	h.send(false, iframe(3, 1))  // 16 bytes forwarded to the client
	h.send(false, iframe(13, 1)) // 32
	// The server sends a control command the policy denies.
	cur, d := h.send(false, iframe(45, 1))
	if d.Action != capture.Drop {
		t.Fatalf("server-side denied APDU = %+v, want Drop", d)
	}
	want := []session.Reset{
		{Src: goldenClient, Dst: goldenServer, Seq: 1}, // 0xfffffff0 + 1 + 16, wrapped
		{Src: goldenServer, Dst: goldenClient, Seq: testServerISN + 1 + 32},
	}
	if got := abortAndResets(t, h, cur); !reflect.DeepEqual(got, want) {
		t.Fatalf("resets = %+v, want %+v", got, want)
	}
}

// TestIECResetGoldenStaleACK: the server's last ACK is older than what was
// forwarded to it (the ACK of the latest data is still in flight). The RST
// uses the forwarded end, never the stale ACK and never withheld bytes.
func TestIECResetGoldenStaleACK(t *testing.T) {
	h := newIECHarness(t, "enforce")
	h.handshake()
	h.send(true, iframe(46, 1))
	h.send(true, iframe(46, 1)) // 32 bytes forwarded; the server ACKs none
	stale := h.pkt(false, capture.TCPFlagACK, h.sSeq, h.clientISN+1, nil)
	if d := h.e.handlePacket(stale); d.Action != h.passingDisposition() {
		t.Fatalf("stale pure ACK = %+v", d)
	}
	held, _ := h.send(true, iframe(46, 1)[:8]) // withheld
	cur, d := h.send(true, append(iframe(46, 1)[8:], iframe(45, 1)...))
	if d.Action != capture.Drop || len(d.Resolved) != 1 || d.Resolved[0].Token != held.Token {
		t.Fatalf("denial = %+v", d)
	}
	h.e.hooks.onVerdict(held.Token, capture.VerdictDrop, nil)
	want := []session.Reset{
		{Src: goldenClient, Dst: goldenServer, Seq: 0x11}, // 0xfffffff0 + 1 + 32, not the stale ACK
		{Src: goldenServer, Dst: goldenClient, Seq: testServerISN + 1},
	}
	if got := abortAndResets(t, h, cur); !reflect.DeepEqual(got, want) {
		t.Fatalf("resets = %+v, want %+v", got, want)
	}
}

// TestIECResetGoldenFINOnHeldPacket: a FIN that arrives on a held packet
// counts once the packet is released, so after the half-close the server's
// RST sits one past the client's data.
func TestIECResetGoldenFINOnHeldPacket(t *testing.T) {
	h := newIECHarness(t, "enforce")
	h.handshake()
	cmd := iframe(46, 1)
	// The tail with the FIN arrives first (out of order) and is held.
	tail := h.pkt(true, capture.TCPFlagACK|capture.TCPFlagFIN, h.cSeq+6, h.sSeq, cmd[6:])
	if d := h.e.handlePacket(tail); d.Action != capture.Hold {
		t.Fatalf("out-of-order tail with FIN = %+v, want Hold", d)
	}
	head := h.pkt(true, capture.TCPFlagACK, h.cSeq, h.sSeq, cmd[:6])
	d := h.e.handlePacket(head)
	if d.Action != h.passingDisposition() || len(d.Resolved) != 1 || d.Resolved[0] != (capture.Resolution{Token: tail.Token, Verdict: capture.VerdictRepeat, Mark: markabi.Continue(tail.Mark, false)}) {
		t.Fatalf("gap fill = %+v, want Repeat releasing the tail", d)
	}
	h.cSeq += 16
	cur, d := h.send(false, iframe(45, 1))
	if d.Action != capture.Drop {
		t.Fatalf("denial after half-close = %+v", d)
	}
	want := []session.Reset{
		{Src: goldenClient, Dst: goldenServer, Seq: 2}, // 0xfffffff0 + 1 + 16 + FIN
		{Src: goldenServer, Dst: goldenClient, Seq: testServerISN + 1},
	}
	if got := abortAndResets(t, h, cur); !reflect.DeepEqual(got, want) {
		t.Fatalf("resets = %+v, want %+v", got, want)
	}
}
