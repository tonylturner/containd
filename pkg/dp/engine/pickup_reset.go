// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 containd Authors

package engine

import (
	"errors"
	"sync"
	"sync/atomic"
	"time"

	"github.com/tonylturner/containd/pkg/common/metrics"
	"github.com/tonylturner/containd/pkg/dp/capture"
	"github.com/tonylturner/containd/pkg/dp/dpi"
	"github.com/tonylturner/containd/pkg/dp/flow"
	"github.com/tonylturner/containd/pkg/dp/session"
)

// closePickedUp closes the connection of an inline flow whose stream has
// just failed as picked up mid-connection, as midstreamLocked closes an
// IEC104 session: the resets observedResets gives for the dropped packet
// are sent once its drop verdict is submitted, and kept for
// iecResetWindow to answer challenge ACKs (answerPickupChallenge). The
// opposite direction's stream fails as picked up too, so that nothing of
// the old connection passes and both directions start again at the next
// handshake. Without a ready injector, and for IPv6, which the injector
// cannot reset, the connection's packets only drop.
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
	key := iecKey{client: src, server: dst}
	if state.Key.Dir == flow.DirReverse {
		key = iecKey{client: dst, server: src}
	}
	var resets connReset
	toReceiver, toSender, hasSender := observedResets(src, dst, pkt.TCP)
	resets.targets[key.target(toReceiver)] = resetTarget{valid: true, r: toReceiver}
	if hasSender {
		resets.targets[key.target(toSender)] = resetTarget{valid: true, r: toSender}
	}
	e.afterDrop(pkt.Token, func() {
		for _, target := range []int{iecDirSrv, iecDirClient} { // as resetJob
			if tr := &resets.targets[target]; tr.valid {
				t.sendPickupReset(key, tr.r)
				tr.sent = time.Now()
			}
		}
		t.pickups.record(key, resets, time.Now())
		t.deleteConntrack(key.client, key.server, key.what())
	})
}

// target is the index of the endpoint r resets.
func (k iecKey) target(r session.Reset) int {
	if r.Dst == k.client {
		return iecDirClient
	}
	return iecDirSrv
}

func (k iecKey) what() string {
	return "picked-up connection " + k.client.String() + " > " + k.server.String()
}

func (t *iecTable) sendPickupReset(key iecKey, r session.Reset) {
	if err := t.sendRST(r); err != nil && t.onError != nil {
		t.onError(errors.New(key.what() + ": " + err.Error()))
	}
}

// answerPickupChallenge answers a challenge ACK (RFC 5961) from an endpoint
// of a picked-up connection the engine reset, as the IEC104 tombstone does
// (connReset.challenge): the reset goes again at the packet's ACK number.
// A handshake segment starts the tuple's next connection, which ends the
// answers, as a new incarnation retires an IEC104 tombstone. It runs
// before the packet is decided; the packet itself drops or passes as any
// other.
func (t *iecTable) answerPickupChallenge(pkt capture.Packet) {
	if t.pickups.live.Load() == 0 || pkt.Proto != 6 || !pkt.TCP.Valid {
		return
	}
	src, okSrc := addrPort(pkt.SrcIP, pkt.SrcPort)
	dst, okDst := addrPort(pkt.DstIP, pkt.DstPort)
	if !okSrc || !okDst {
		return
	}
	if pkt.TCP.Flags&capture.TCPFlagSYN != 0 && handshakeMarked(pkt) {
		t.pickups.forget(iecKey{client: src, server: dst}, iecKey{client: dst, server: src})
		return
	}
	now := time.Now()
	key, from := iecKey{client: src, server: dst}, iecDirClient
	r, ok := t.pickups.challenge(key, from, pkt.TCP, now)
	if !ok {
		key, from = iecKey{client: dst, server: src}, iecDirSrv
		if r, ok = t.pickups.challenge(key, from, pkt.TCP, now); !ok {
			return
		}
	}
	if !t.jobs.submit(func() {
		t.sendPickupReset(key, r)
		t.pickups.resent(key, from, time.Now())
	}) {
		pressureTotals.worker.Add(1)
		metrics.IEC104ResetWorkerRejectionsTotal.Inc()
		t.health.fault(faultWorker, "reset worker queue full")
	}
}

// pickupResets keeps the resets of picked-up connections for
// iecResetWindow after they were sent, for answerPickupChallenge. It holds
// at most iecMaxSessions connections; live lets the packet path skip it
// when it holds none.
type pickupResets struct {
	mu    sync.Mutex
	conns map[iecKey]*connReset
	swept time.Time
	live  atomic.Int32
}

func newPickupResets() *pickupResets {
	return &pickupResets{conns: make(map[iecKey]*connReset)}
}

// record keeps the resets sent to close a connection.
func (p *pickupResets) record(key iecKey, resets connReset, now time.Time) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.expireLocked(now)
	if _, ok := p.conns[key]; !ok && len(p.conns) >= iecMaxSessions {
		return
	}
	p.conns[key] = &resets
	p.live.Store(int32(len(p.conns)))
}

// challenge returns the reset to send again for a packet of from on key.
func (p *pickupResets) challenge(key iecKey, from int, tcp capture.TCPMeta, now time.Time) (session.Reset, bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if now.Sub(p.swept) > iecResetWindow {
		p.expireLocked(now)
	}
	return p.conns[key].challenge(from, tcp, now)
}

// forget drops the resets of the keys.
func (p *pickupResets) forget(keys ...iecKey) {
	p.mu.Lock()
	defer p.mu.Unlock()
	for _, key := range keys {
		delete(p.conns, key)
	}
	p.live.Store(int32(len(p.conns)))
}

// resent restarts the challenge window of a target after a resent reset.
func (p *pickupResets) resent(key iecKey, target int, now time.Time) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if c := p.conns[key]; c != nil {
		c.targets[target].sent = now
	}
}

// expireLocked drops the connections whose every reset is older than
// iecResetWindow.
func (p *pickupResets) expireLocked(now time.Time) {
	p.swept = now
	for key, c := range p.conns {
		live := false
		for _, tr := range c.targets {
			live = live || tr.valid && now.Sub(tr.sent) <= iecResetWindow
		}
		if !live {
			delete(p.conns, key)
		}
	}
	p.live.Store(int32(len(p.conns)))
}
