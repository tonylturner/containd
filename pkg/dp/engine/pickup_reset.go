// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 containd Authors

package engine

import (
	"sync"
	"sync/atomic"
	"time"

	"github.com/tonylturner/containd/pkg/common/metrics"
	"github.com/tonylturner/containd/pkg/dp/capture"
	"github.com/tonylturner/containd/pkg/dp/events"
	"github.com/tonylturner/containd/pkg/dp/flow"
	"github.com/tonylturner/containd/pkg/dp/ics/eventfields"
	"github.com/tonylturner/containd/pkg/dp/session"
)

// resetDeniedTCP generalizes pickup resets: the denied packet seeds best-effort
// resets for both peers, followed by exact conntrack deletion after its drop.
// IPv6 and an unavailable injector still produce per-peer outcome evidence.
func (e *Engine) resetDeniedTCP(pkt capture.Packet, state *flow.State, proto, reason string, d *deniedTCP) {
	t := e.iec
	src, okSrc := addrPort(pkt.SrcIP, pkt.SrcPort)
	dst, okDst := addrPort(pkt.DstIP, pkt.DstPort)
	available := okSrc && okDst && pkt.TCP.Valid && t.health.injectorReady()
	key := iecKey{client: src, server: dst}
	if state.Key.Dir == flow.DirReverse {
		key = iecKey{client: dst, server: src}
	}
	var resets connReset
	toReceiver, toSender, hasSender := observedResets(src, dst, pkt.TCP)
	receiver, sender := iecDirSrv, iecDirClient
	if state.Key.Dir == flow.DirReverse {
		receiver, sender = sender, receiver
	}
	resets.targets[receiver] = resetTarget{valid: true, r: toReceiver}
	if hasSender {
		resets.targets[sender] = resetTarget{valid: true, r: toSender}
	}
	e.afterDrop(pkt.Token, func() {
		d.mu.Lock()
		defer d.mu.Unlock()
		if d.retired {
			for _, target := range []int{iecDirSrv, iecDirClient} {
				e.genericResetEvent(state, proto, reason, target, "unavailable", nil)
			}
			return
		}
		for _, target := range []int{iecDirSrv, iecDirClient} { // as resetJob
			tr := &resets.targets[target]
			outcome := "unavailable"
			var err error
			if available && tr.valid {
				err = t.sendRST(tr.r)
				outcome = resetOutcome(err)
				tr.sent = time.Now()
			}
			e.genericResetEvent(state, proto, reason, target, outcome, err)
		}
		if available {
			t.pickups.record(key, resets, d, func(target int, err error) {
				e.genericResetEvent(state, proto, reason, target, resetOutcome(err), err)
			}, time.Now())
			t.deleteConntrack(key.client, key.server, key.what())
		}
	})
}

func (e *Engine) genericResetEvent(state *flow.State, proto, reason string, target int, outcome string, err error) {
	attrs := map[string]any{eventfields.KeyOutcome: outcome, eventfields.KeyTarget: targetNames[target], eventfields.KeyReason: reason}
	if err != nil {
		attrs[eventfields.KeyError] = err.Error()
		if e.iec.onError != nil {
			e.iec.onError(err)
		}
	}
	k := state.Key
	if k.Dir == flow.DirReverse {
		k = k.Reversed()
	}
	e.eventStore.Append(events.Event{FlowID: state.ID(), Proto: proto, Kind: eventfields.KindSession,
		Timestamp: time.Now().UTC(), SrcIP: k.SrcIP.String(), DstIP: k.DstIP.String(), SrcPort: k.SrcPort, DstPort: k.DstPort,
		Transport: "tcp", Attributes: attrs})
}

func (k iecKey) what() string {
	return "denied connection " + k.client.String() + " > " + k.server.String()
}

func resetOutcome(err error) string {
	if err != nil {
		return outcomeResetFailed
	}
	return outcomeResetSent
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
	r, entry, ok := t.pickups.challenge(key, from, pkt.TCP, now)
	if !ok {
		key, from = iecKey{client: dst, server: src}, iecDirSrv
		if r, entry, ok = t.pickups.challenge(key, from, pkt.TCP, now); !ok {
			return
		}
	}
	if !t.jobs.submit(func() {
		entry.guard.mu.Lock()
		defer entry.guard.mu.Unlock()
		if entry.guard.retired {
			return
		}
		err := t.sendRST(r)
		entry.report(from, err)
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
	conns map[iecKey]*pickupReset
	swept time.Time
	live  atomic.Int32
}

// pickupReset associates challenge retries with the same denial generation.
// Reconnect retirement cancels queued retries before they can hit a new session.
type pickupReset struct {
	connReset
	guard  *deniedTCP
	report func(int, error)
}

func newPickupResets() *pickupResets {
	return &pickupResets{conns: make(map[iecKey]*pickupReset)}
}

// record keeps the resets sent to close a connection.
func (p *pickupResets) record(key iecKey, resets connReset, guard *deniedTCP, report func(int, error), now time.Time) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.expireLocked(now)
	if _, ok := p.conns[key]; !ok && len(p.conns) >= iecMaxSessions {
		return
	}
	p.conns[key] = &pickupReset{connReset: resets, guard: guard, report: report}
	p.live.Store(int32(len(p.conns)))
}

// challenge returns the reset to send again for a packet of from on key.
func (p *pickupResets) challenge(key iecKey, from int, tcp capture.TCPMeta, now time.Time) (session.Reset, *pickupReset, bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if now.Sub(p.swept) > iecResetWindow {
		p.expireLocked(now)
	}
	entry := p.conns[key]
	if entry == nil {
		return session.Reset{}, nil, false
	}
	r, ok := entry.challenge(from, tcp, now)
	return r, entry, ok
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
