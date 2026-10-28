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
	"github.com/tonylturner/containd/pkg/dp/session"
)

// The engine closes a connection it drops but cannot follow, an IEC104
// session not observed from its SYN (midstreamLocked) or an inline flow
// denied or uninspectable stream (closeDeniedTCP), so that both endpoints
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

// connReset is the reset state of a connection the engine closed, per
// target endpoint (index iecDirClient or iecDirSrv).
type connReset struct {
	targets [2]resetTarget
}

type resetTarget struct {
	valid   bool
	r       session.Reset
	sent    time.Time
	retries int
}

// challenge answers a challenge ACK (RFC 5961) that target from sent after
// its reset: any of its packets that carries ACK and no RST. The reset
// goes again at the ACK number, at most iecResetRetries times, within
// iecResetWindow of the last one. It returns the reset to send.
func (c *connReset) challenge(from int, tcp capture.TCPMeta, now time.Time) (session.Reset, bool) {
	if c == nil || tcp.Flags&capture.TCPFlagACK == 0 || tcp.Flags&capture.TCPFlagRST != 0 {
		return session.Reset{}, false
	}
	tr := &c.targets[from]
	if !tr.valid || tr.sent.IsZero() || tr.retries >= iecResetRetries || now.Sub(tr.sent) > iecResetWindow || tcp.Ack == tr.r.Seq {
		return session.Reset{}, false
	}
	tr.retries++
	tr.r.Seq = tcp.Ack
	return tr.r, true
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
