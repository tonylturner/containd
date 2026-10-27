// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

package engine

import (
	"errors"
	"sort"
	"strings"
	"time"

	"github.com/tonylturner/containd/pkg/common/metrics"
	"github.com/tonylturner/containd/pkg/dp/capture"
	"github.com/tonylturner/containd/pkg/dp/events"
	"github.com/tonylturner/containd/pkg/dp/ics/eventfields"
	"github.com/tonylturner/containd/pkg/dp/session"
)

var (
	errInjectorUnavailable = errors.New("reset injector unavailable")
	errNotInline           = errors.New("capture is not inline")
)

// iecActions is the work an IEC104 state change produces. It is collected
// under the session lock and carried out after the lock is released.
type iecActions struct {
	drops             []capture.Resolution // held tokens to drop
	events            []events.Event
	jobs              []func()
	inventoryObserve  []*iecInventoryCommand
	inventoryOutcome  []*iecInventoryCommand
	inventoryOverflow uint64
	// retired reports that the tuple's connection ended or a new one
	// started on it, so the engine ends the connection's conformance
	// alert identity.
	retired bool
}

func (a *iecActions) merge(b iecActions) {
	a.drops = append(a.drops, b.drops...)
	a.events = append(a.events, b.events...)
	a.jobs = append(a.jobs, b.jobs...)
	a.inventoryObserve = append(a.inventoryObserve, b.inventoryObserve...)
	a.inventoryOutcome = append(a.inventoryOutcome, b.inventoryOutcome...)
	a.inventoryOverflow += b.inventoryOverflow
	a.retired = a.retired || b.retired
}

// abortTxn waits for the verdict completions of an aborted session's
// dropped packets before it reports ics.verdict and starts the resets.
type abortTxn struct {
	s       *iecSession
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
// verdict completion. A learn envelope never aborts; callers ensure that.
func (t *iecTable) abortLocked(s *iecSession, reason *iecAbortReason, trigger string, cur *heldPacket, now time.Time) iecActions {
	var acts iecActions
	if s.state == iecAborted {
		return acts
	}
	acts.merge(t.endInventoryLocked(s))
	acts.retired = true
	countIECAbort(reason)
	dropped := append([]*heldPacket(nil), s.held...)
	if cur != nil {
		dropped = append(dropped, cur)
	}
	txn := &abortTxn{s: s, apdus: t.droppedAPDUsLocked(s, dropped), trigger: trigger}
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
	s.state, s.endedAt = iecAborted, now
	s.apci = nil
	t.tombstones++
	t.evictTombstoneLocked()
	s.reset = resetTargets(s)
	t.dpi.EndStream(s.id)
	if t.markAbort != nil {
		t.markAbort(s.id)
	}
	t.reconnect[pairKey(s.client, s.server)] = now
	acts.events = append(acts.events, s.sessionEvent(outcomeAborted, map[string]any{eventfields.KeyReason: reason.name}, now))
	if txn.pending == 0 {
		acts.merge(t.finishLocked(txn, now))
	}
	return acts
}

// droppedAPDUsLocked lists every identified APDU whose bytes the dropped
// packets carry: decided frames they overlap, and the known start of the
// incomplete tail. Unknown boundaries get no ID.
func (t *iecTable) droppedAPDUsLocked(s *iecSession, dropped []*heldPacket) []string {
	seen := map[string]bool{}
	var ids []string
	add := func(dir int, start int64) {
		id := eventfields.APDUID(s.id, dirLetter(dir), start)
		if !seen[id] {
			seen[id] = true
			ids = append(ids, id)
		}
	}
	for _, h := range dropped {
		d := s.dirs[h.dir]
		if d == nil {
			continue
		}
		for _, f := range d.frames {
			if f.start < h.end && h.off < f.end {
				add(h.dir, f.start)
			}
		}
		if d.framedEnd < d.bytes.Next() && h.end > d.framedEnd {
			add(h.dir, d.framedEnd)
		}
	}
	sort.Strings(ids)
	return ids
}

func dirLetter(dir int) byte {
	if dir == iecDirClient {
		return eventfields.DirClient
	}
	return eventfields.DirServer
}

// resetTargets computes one RST per endpoint: for target X, seq is the end
// of the last byte forwarded to X. Without both ISNs the
// connection was never established and nothing is reset.
func resetTargets(s *iecSession) *connReset {
	c2s, s2c := s.dirs[iecDirClient], s.dirs[iecDirSrv]
	if c2s == nil || s2c == nil {
		return &connReset{}
	}
	return &connReset{targets: [2]resetTarget{
		iecDirClient: {valid: true, r: session.Reset{Src: s.server, Dst: s.client, Seq: forwardedSeq(s2c)}},
		iecDirSrv:    {valid: true, r: session.Reset{Src: s.client, Dst: s.server, Seq: forwardedSeq(c2s)}},
	}}
}

func forwardedSeq(d *iecDir) uint32 {
	end := d.forwarded
	if d.finFwd {
		end++
	}
	return d.seq.Seq(end)
}

// finishLocked reports ics.verdict and starts the resets.
func (t *iecTable) finishLocked(txn *abortTxn, now time.Time) iecActions {
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
	return iecActions{
		events: []events.Event{txn.s.event(eventfields.KindVerdict, attrs, now)},
		jobs:   []func(){t.resetJob(txn.s)},
	}
}

// completeLocked records one verdict completion of an aborted session.
func (t *iecTable) completeLocked(tok capture.Token, err error, now time.Time) iecActions {
	txn := t.aborts[tok]
	if txn == nil {
		return iecActions{}
	}
	delete(t.aborts, tok)
	txn.pending--
	if err != nil {
		txn.errs = append(txn.errs, err.Error())
	}
	if txn.pending > 0 {
		return iecActions{}
	}
	return t.finishLocked(txn, now)
}

// resetJob sends the resets of an aborted session and then deletes its
// conntrack entry. It runs on the worker, never under the session lock.
func (t *iecTable) resetJob(s *iecSession) func() {
	return func() {
		for _, target := range []int{iecDirSrv, iecDirClient} {
			t.mu.Lock()
			tr := s.reset.targets[target]
			t.mu.Unlock()
			if tr.valid {
				t.sendReset(s, target, tr.r)
			}
		}
		t.mu.Lock()
		established := s.reset.targets[iecDirSrv].valid
		t.mu.Unlock()
		if established {
			t.deleteConntrack(s.client, s.server, "iec104 abort "+s.id)
		}
	}
}

// sendReset sends one RST and reports it. A failure keeps the session
// dropped and makes enforcement unhealthy.
func (t *iecTable) sendReset(s *iecSession, target int, r session.Reset) {
	err := t.sendRST(r)
	t.mu.Lock()
	now := t.now()
	s.reset.targets[target].sent = now
	t.mu.Unlock()
	extra := map[string]any{eventfields.KeyTarget: targetNames[target]}
	outcome := outcomeResetSent
	if err != nil {
		outcome = outcomeResetFailed
		pressureTotals.injector.Add(1)
		metrics.IEC104InjectorFailuresTotal.Inc()
		extra[eventfields.KeyError] = err.Error()
	}
	t.emit([]events.Event{s.sessionEvent(outcome, extra, now)})
}

// challengeLocked answers a challenge ACK from a reset target of an aborted
// session (connReset.challenge).
func (t *iecTable) challengeLocked(s *iecSession, from int, pkt capture.Packet, now time.Time) iecActions {
	r, ok := s.reset.challenge(from, pkt.TCP, now)
	if !ok {
		return iecActions{}
	}
	return iecActions{jobs: []func(){func() { t.sendReset(s, from, r) }}}
}

// apply carries out actions after the session lock is released: drops are
// settled (a rejected request gets no completion, so it completes here),
// then events are emitted and jobs queued.
func (t *iecTable) apply(acts iecActions) {
	if len(acts.drops) > 0 {
		errs := t.settle(acts.drops)
		t.mu.Lock()
		now := t.now()
		for i, err := range errs {
			if err != nil {
				countIECVerdictFailure(err)
				acts.merge(t.completeLocked(acts.drops[i].Token, err, now))
			}
		}
		t.mu.Unlock()
		acts.drops = nil
	}
	t.finish(acts)
}

// finish emits events and queues jobs; drops were resolved by the caller.
func (t *iecTable) finish(acts iecActions) {
	t.finishInventory(acts)
	if len(acts.events) > 0 {
		t.emit(acts.events)
	}
	for _, job := range acts.jobs {
		if !t.jobs.submit(job) {
			pressureTotals.worker.Add(1)
			metrics.IEC104ResetWorkerRejectionsTotal.Inc()
			t.health.fault(faultWorker, "reset worker queue full")
		}
	}
}

func (t *iecTable) settle(res []capture.Resolution) []error {
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
func (t *iecTable) onVerdict(tok capture.Token, v capture.Verdict, err error) {
	t.mu.Lock()
	countIECVerdictFailure(err)
	now := t.now()
	acts := t.completeLocked(tok, err, now)
	t.inventoryVerdictLocked(tok, v, err, &acts)
	if s := t.held[tok]; s != nil {
		t.unholdLocked(s, tok)
	}
	t.mu.Unlock()
	t.finish(acts)
}

func (t *iecTable) unholdLocked(s *iecSession, tok capture.Token) {
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
func (t *iecTable) onSourceDown() {
	var acts iecActions
	t.mu.Lock()
	t.pressureOffline = true
	now := t.now()
	for _, s := range t.sessions {
		if s.mode == "enforce" && (s.state == iecSynSent || s.state == iecEstablished) {
			a := t.abortLocked(s, abortQueue, "", nil, now)
			a.drops = nil
			acts.merge(a)
		}
	}
	t.mu.Unlock()
	t.finish(acts)
}
