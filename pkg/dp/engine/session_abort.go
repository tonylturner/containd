// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

package engine

import (
	"errors"
	"strings"
	"time"

	"github.com/tonylturner/containd/pkg/common/metrics"
	"github.com/tonylturner/containd/pkg/dp/capture"
	"github.com/tonylturner/containd/pkg/dp/flow"
	"github.com/tonylturner/containd/pkg/dp/ics/eventfields"
	"github.com/tonylturner/containd/pkg/dp/inventory"
	"github.com/tonylturner/containd/pkg/dp/session"
)

var (
	errInjectorUnavailable = errors.New("reset injector unavailable")
	errNotInline           = errors.New("capture is not inline")
)

// sessionActions is the work a session state change produces. It is collected
// under the session lock and carried out after the lock is released.
type sessionActions struct {
	drops            []capture.Resolution // held tokens to drop
	events           []iecTelemetry
	jobs             []func()
	inventoryObserve []inventory.IEC104Observation
	// retired reports that the tuple's connection ended or a new one
	// started on it, so the engine ends the connection's conformance
	// alert identity.
	retired bool
}

func (a *sessionActions) merge(b sessionActions) {
	a.drops = append(a.drops, b.drops...)
	a.events = append(a.events, b.events...)
	a.jobs = append(a.jobs, b.jobs...)
	a.inventoryObserve = append(a.inventoryObserve, b.inventoryObserve...)
	a.retired = a.retired || b.retired
}

// abortTxn waits for the verdict completions of an aborted session's
// dropped packets before it reports ics.verdict and starts the resets.
type abortTxn struct {
	s       *trackedSession
	pending int
	errs    []string
	apdus   []string
	trigger string
}

var targetNames = [2]string{"client", "server"}

// abortLocked begins the abort transaction: it marks the incarnation
// aborted before anything is released, drops every
// held packet (returned in drops) and the current packet cur, and keeps the
// session as a tombstone. The resets start once every drop has its
// verdict completion. A monitor envelope never aborts; callers ensure that.
func (t *sessionTable) abortLocked(s *trackedSession, reason *iecAbortReason, trigger string, cur *heldPacket, now time.Time) sessionActions {
	var acts sessionActions
	if t.detached || s.state == sessionAborted {
		return acts
	}
	acts.retired = true
	t.countAbort(reason)
	dropped := append([]*heldPacket(nil), s.held...)
	if cur != nil {
		dropped = append(dropped, cur)
	}
	txn := &abortTxn{s: s, apdus: t.iecAdapter.droppedAPDUsLocked(s, dropped), trigger: trigger}
	for _, h := range s.held {
		delete(t.held, h.tok)
		t.aborts[h.tok] = txn
		txn.pending++
		acts.drops = append(acts.drops, capture.Resolution{Token: h.tok, Verdict: capture.VerdictDrop})
	}
	t.heldTotal -= len(s.held)
	s.held, s.heldBytes = nil, 0
	if cur != nil {
		if cur.tok.Inline() {
			t.aborts[cur.tok] = txn
			txn.pending++
		} else {
			txn.errs = append(txn.errs, errNotInline.Error())
		}
	}
	acts.merge(t.retainDenialLocked(s, now))
	s.reset = resetTargets(s)
	s.next.releaseInspection()
	s.next = nil
	s.clearInspectionBytes()
	t.dpi.EndStream(s.id)
	if t.markAbort != nil {
		t.markAbort(s.id)
	}
	t.rememberReconnectLocked(s.client, s.server, now)
	acts.events = append(acts.events, s.sessionEvent(outcomeAborted, map[string]any{eventfields.KeyReason: reason.name}, now))
	if txn.pending == 0 {
		acts.merge(t.finishLocked(txn, now))
	}
	return acts
}

// resetTargets computes one RST per endpoint: for target X, seq is the end
// of the last byte forwarded to X. Without both ISNs the
// connection was never established and nothing is reset.
func resetTargets(s *trackedSession) *connReset {
	c2s, s2c := s.dirs[sessionDirClient], s.dirs[sessionDirSrv]
	if c2s == nil || s2c == nil {
		return &connReset{}
	}
	return &connReset{targets: [2]resetTarget{
		sessionDirClient: {valid: true, r: session.Reset{Src: s.server, Dst: s.client, Seq: forwardedSeq(s2c)}},
		sessionDirSrv:    {valid: true, r: session.Reset{Src: s.client, Dst: s.server, Seq: forwardedSeq(c2s)}},
	}}
}

func forwardedSeq(d *sessionDir) uint32 {
	end := d.forwarded
	if d.finFwd {
		end++
	}
	return d.seq.Seq(end)
}

// finishLocked reports ics.verdict and starts the resets.
func (t *sessionTable) finishLocked(txn *abortTxn, now time.Time) sessionActions {
	attrs := map[string]any{
		eventfields.KeyOutcome: outcomeDropped,
		eventfields.KeyAPDUIDs: append([]string{}, txn.apdus...),
	}
	if txn.trigger != "" {
		attrs[eventfields.KeyTriggerAPDUID] = txn.trigger
	}
	if len(txn.errs) > 0 {
		attrs[eventfields.KeyOutcome] = outcomeDropFailed
		attrs[eventfields.KeyError] = strings.Join(txn.errs, "; ")
	}
	return sessionActions{
		events: []iecTelemetry{txn.s.event(eventfields.KindVerdict, attrs, now)},
		jobs:   []func(){t.resetJob(txn.s)},
	}
}

// completeLocked records one verdict completion of an aborted session.
func (t *sessionTable) completeLocked(tok capture.Token, err error, now time.Time) sessionActions {
	txn := t.aborts[tok]
	if txn == nil {
		return sessionActions{}
	}
	delete(t.aborts, tok)
	txn.pending--
	if err != nil && !errors.Is(err, capture.ErrTokenFlushed) {
		txn.errs = append(txn.errs, err.Error())
	}
	if txn.pending > 0 {
		return sessionActions{}
	}
	return t.finishLocked(txn, now)
}

// resetJob sends the resets of an aborted session and then deletes its
// conntrack entry. It runs on the worker, never under the session lock.
func (t *sessionTable) resetJob(s *trackedSession) func() {
	var connection *flow.Connection
	if s.flow != nil {
		connection = s.flow.Connection.Load()
	}
	return t.resetWork(s, func() {
		for _, target := range []int{sessionDirSrv, sessionDirClient} {
			t.mu.Lock()
			tr := s.reset.targets[target]
			t.mu.Unlock()
			if tr.valid {
				t.sendReset(s, target, tr.r)
			}
		}
		t.mu.Lock()
		established := s.reset.targets[sessionDirSrv].valid
		t.mu.Unlock()
		if established && t.health.injectorReady() {
			t.deleteConntrack(s.client, s.server, connection, "iec104 abort "+s.id)
		}
	}, func() {
		t.mu.Lock()
		var events []iecTelemetry
		for _, target := range targetNames {
			events = append(events, s.sessionEvent("unavailable", map[string]any{eventfields.KeyTarget: target}, t.now()))
		}
		t.mu.Unlock()
		t.emit(events)
	})
}

// sendReset sends one RST and reports it. A failure keeps the session
// dropped and makes enforcement unhealthy.
func (t *sessionTable) sendReset(s *trackedSession, target int, r session.Reset) {
	outcome := "unavailable"
	err := errInjectorUnavailable
	if t.health.injectorReady() {
		err = t.sendRST(r)
		outcome = resetOutcome(err)
	}
	t.mu.Lock()
	now := t.now()
	s.reset.targets[target].sent = now
	t.mu.Unlock()
	extra := map[string]any{eventfields.KeyTarget: targetNames[target]}
	if err != nil {
		pressureTotals.injector.Add(1)
		metrics.IEC104InjectorFailuresTotal.Inc()
		extra[eventfields.KeyError] = err.Error()
	}
	t.mu.Lock()
	ev := s.sessionEvent(outcome, extra, now)
	t.mu.Unlock()
	t.emit([]iecTelemetry{ev})
	if err != nil && t.onError != nil {
		t.onError(err)
	}
}

// challengeLocked answers a challenge ACK from a reset target of an aborted
// session (connReset.challenge).
func (t *sessionTable) challengeLocked(s *trackedSession, from int, pkt capture.Packet, now time.Time) sessionActions {
	if !resetChallengeACK(pkt) {
		return sessionActions{}
	}
	r, ok := s.reset.challenge(from, pkt.TCP, now)
	if !ok {
		return sessionActions{}
	}
	return sessionActions{jobs: []func(){t.resetWork(s, func() { t.sendReset(s, from, r) }, nil)}}
}

// apply carries out actions after the session lock is released: drops are
// settled (a rejected request gets no completion, so it completes here),
// then events are emitted and jobs queued.
func (t *sessionTable) apply(acts sessionActions) {
	if len(acts.drops) > 0 {
		errs := t.settle(acts.drops)
		t.mu.Lock()
		now := t.now()
		for i, err := range errs {
			if err != nil {
				if residencySettled(err) {
					t.releaseHeldCreditLocked(acts.drops[i].Token)
				}
				t.countVerdictFailure(err)
				acts.merge(t.completeLocked(acts.drops[i].Token, err, now))
			}
		}
		t.mu.Unlock()
		acts.drops = nil
	}
	t.finish(acts)
}

// finish emits events and queues jobs; drops were resolved by the caller.
func (t *sessionTable) finish(acts sessionActions) {
	for _, observation := range acts.inventoryObserve {
		t.inventory.ObserveIEC104(observation)
	}
	if len(acts.events) > 0 {
		t.emit(acts.events)
	}
	if t.detached {
		return
	}
	for _, job := range acts.jobs {
		if !t.jobs.submit(job) {
			pressureTotals.worker.Add(1)
			metrics.IEC104ResetWorkerRejectionsTotal.Inc()
			t.health.fault(faultWorker, "reset worker queue full")
		}
	}
}

func (t *sessionTable) settle(res []capture.Resolution) []error {
	var settler capture.Settler
	if t.settler != nil {
		settler = t.settler()
	}
	if settler == nil {
		errs := make([]error, len(res))
		for i := range errs {
			errs[i] = capture.ErrNotInline
		}
		return errs
	}
	return settler.Settle(res...)
}

// onVerdict records a verdict completion. A held token completes only when
// its generation went down: the kernel dropped it, so it leaves the ledger.
func (t *sessionTable) onVerdict(tok capture.Token, v capture.Verdict, err error) {
	t.mu.Lock()
	s, expected := t.tokenOwnerLocked(tok)
	if residencySettled(err) {
		t.releaseHeldCreditLocked(tok)
	}
	t.countVerdictFailure(err)
	now := t.now()
	acts := t.completeLocked(tok, err, now)
	if s != nil && t.sessions[sessionKey{s.client, s.server}] == s && s.mode == "enforce" && (s.state == sessionEstablished || s.state == sessionSynSent) && (err != nil || v != expected) {
		acts.merge(t.abortLocked(s, abortTransport, "", nil, now))
	}
	if s := t.held[tok]; s != nil {
		t.unholdLocked(s, tok)
	}
	t.mu.Unlock()
	t.apply(acts)
}

func (t *sessionTable) unholdLocked(s *trackedSession, tok capture.Token) {
	delete(t.held, tok)
	for i, h := range s.held {
		if h.tok == tok {
			s.heldBytes -= int(h.end - h.off)
			s.held = append(s.held[:i], s.held[i+1:]...)
			t.heldTotal--
			return
		}
	}
}

// onSourceDown aborts every enforce session when the inline queue goes
// down: its held packets are gone and its byte ledger can no longer be
// trusted. The kernel already dropped the held packets; their
// completions (ErrQueueClosed) finish the aborts.
func (t *sessionTable) onSourceDown(generation ...uint64) {
	var acts sessionActions
	t.mu.Lock()
	gen := uint64(0)
	if len(generation) != 0 {
		gen = generation[0]
	}
	t.flushHeldCreditsLocked(gen)
	t.pressureOffline = true
	now := t.now()
	for _, s := range t.sessions {
		if s.mode == "enforce" && (s.state == sessionSynSent || s.state == sessionEstablished) {
			a := t.abortLocked(s, abortQueue, "", nil, now)
			a.drops = nil
			acts.merge(a)
		}
	}
	t.mu.Unlock()
	t.finish(acts)
}
