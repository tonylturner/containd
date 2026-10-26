// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 containd Authors

package engine

import (
	"context"
	"errors"
	"net/netip"
	"time"

	"github.com/tonylturner/containd/pkg/dp/capture"
	"github.com/tonylturner/containd/pkg/dp/conntrack"
	"github.com/tonylturner/containd/pkg/dp/dpi"
	"github.com/tonylturner/containd/pkg/dp/flow"
	"github.com/tonylturner/containd/pkg/dp/session"
)

// The engine closes a connection it drops but cannot follow, an IEC104
// session not observed from its SYN (midstreamLocked) or an inline flow
// stream picked up mid-connection (closePickedUp), so that both endpoints
// learn of it at once instead of retransmitting into the drop until their
// own timeouts. It sends one payload-free RST to each endpoint through the
// IEC104 reset injector and then deletes the connection's conntrack entry,
// so that the client's next SYN on the tuple starts a new connection
// (enforce.HandshakeMark).

// observedResets returns the resets that close a connection the engine saw
// only from one packet sent from src to dst: its receiver expects the
// packet's sequence number, and its sender's receive point is the packet's
// acknowledgment number, known only when the packet carries ACK
// (hasSender).
func observedResets(src, dst netip.AddrPort, tcp capture.TCPMeta) (toReceiver, toSender session.Reset, hasSender bool) {
	toReceiver = session.Reset{Src: src, Dst: dst, Seq: tcp.Seq}
	if tcp.Flags&capture.TCPFlagACK == 0 {
		return toReceiver, session.Reset{}, false
	}
	return toReceiver, session.Reset{Src: dst, Dst: src, Seq: tcp.Ack}, true
}

// sendRST sends one reset. A failure makes enforcement unhealthy.
func (t *iecTable) sendRST(r session.Reset) error {
	err := errInjectorUnavailable
	if t.injector != nil {
		err = t.injector.SendRST(r)
	}
	if err != nil {
		t.health.fault(faultReset, "reset: "+err.Error())
	}
	return err
}

// deleteConntrack deletes the conntrack entry of a connection the engine
// reset; what names the connection in the error report.
func (t *iecTable) deleteConntrack(client, server netip.AddrPort, what string) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	err := t.ctDelete(ctx, conntrack.DeleteRequest{
		Proto: "tcp",
		Src:   client.Addr().String(),
		Dst:   server.Addr().String(),
		Sport: int(client.Port()),
		Dport: int(server.Port()),
	})
	if err != nil && t.onError != nil {
		t.onError(errors.New(what + ": conntrack delete: " + err.Error()))
	}
}

// closePickedUp closes the connection of an inline flow whose stream has
// just failed as picked up mid-connection, as midstreamLocked closes an
// IEC104 session: the resets observedResets gives for the dropped packet
// are sent once its drop verdict is submitted. The opposite direction's
// stream fails as picked up too, so that nothing of the old connection
// passes and both directions start again at the next handshake. Without a
// ready injector, and for IPv6, which the injector cannot reset, the
// connection's packets only drop.
func (e *Engine) closePickedUp(pkt capture.Packet, state *flow.State) {
	t := e.iec
	src, okSrc := addrPort(pkt.SrcIP, pkt.SrcPort)
	dst, okDst := addrPort(pkt.DstIP, pkt.DstPort)
	if !okSrc || !okDst || !pkt.TCP.Valid || !t.health.injectorReady() {
		return
	}
	e.flowMu.Lock()
	rev := e.flows[state.Key.Reversed().Hash()]
	e.flowMu.Unlock()
	if rev != nil {
		e.dpiMgr.FailStream(rev, &dpi.ParsedPacket{Proto: "tcp", FailClosed: true}, dpi.StreamMidStream)
	}
	client, server := src, dst
	if state.Key.Dir == flow.DirReverse {
		client, server = dst, src
	}
	toReceiver, toSender, hasSender := observedResets(src, dst, pkt.TCP)
	resets := []session.Reset{toReceiver}
	if hasSender {
		resets = append(resets, toSender)
	}
	what := "picked-up connection " + client.String() + " > " + server.String()
	e.afterDrop(pkt.Token, func() {
		for _, r := range resets {
			if err := t.sendRST(r); err != nil && t.onError != nil {
				t.onError(errors.New(what + ": " + err.Error()))
			}
		}
		t.deleteConntrack(client, server, what)
	})
}
