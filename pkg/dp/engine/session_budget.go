// SPDX-License-Identifier: Apache-2.0
package engine

import (
	"net/netip"
	"time"

	"github.com/tonylturner/containd/pkg/dp/flow"
	"github.com/tonylturner/containd/pkg/dp/limits"
	"github.com/tonylturner/containd/pkg/dp/rules"
)

func (t *sessionTable) allocateSessionLocked(client, server netip.AddrPort, ctx rules.EvalContext, mode string, state *flow.State, now time.Time) *trackedSession {
	class := limits.ClassObserve
	if mode == "enforce" {
		class = limits.ClassEnforce
	}
	memory := flow.NewInspectionMemory(t.resources, class, limits.CategoryStream)
	if !memory.Reserve(int(limits.IECSessionMetadataBytes)) {
		return nil
	}
	// The fixed credit includes held-list slots and abort bookkeeping, so
	// a terminal failure never needs another allocation reservation.
	return &trackedSession{memory: memory, id: t.newID(), flow: retainedSessionState(state),
		pairing: newPairing(sessionProtocol(state), t.resources, mode == "monitor", &t.pairingTotal),
		client:  client, server: server, iecSession: iecSession{ctx: ctx, mode: mode}, lastSeen: now,
		held: make([]*heldPacket, 0, sessionMaxHeldPerSession)}
}

func (t *sessionTable) admissionLimitLocked(mode string) sessionResult {
	t.ledger.Record(limits.TableInspection, limits.ReasonRefused, limits.Mode(mode))
	res := accepted(reasonIECUntracked)
	if mode == "enforce" {
		t.countAbort(abortBound)
		res = dropped("state_limit")
	}
	res.stateLimit = true
	return res
}

func (t *sessionTable) allocateDirLocked(s *trackedSession, dir int, isn uint32) error {
	stream, err := flow.NewBudgetedByteStream(sessionStreamMaxBytes, sessionStreamMaxSegments, t.resources, s.mode == "enforce")
	if err != nil {
		return err
	}
	if old := s.dirs[dir]; old != nil {
		old.bytes.Release()
		old.frames = nil
		if old.frameLease != nil {
			old.frameLease.Release()
		}
	}
	s.dirs[dir] = &sessionDir{hasISN: true, isn: isn, seq: flow.NewSeqSpace(isn), bytes: stream}
	return nil
}

func (t *sessionTable) inspectionLimitLocked(s *trackedSession, cur *heldPacket, now time.Time) sessionResult {
	first := !s.inspectionLost
	if first {
		t.ledger.Record(limits.TableInspection, limits.ReasonRefused, limits.Mode(s.mode))
		s.inspectionLost = true
	}
	res := accepted(reasonIECAccept)
	if s.mode == "enforce" {
		res = droppedWith("state_limit", t.abortLocked(s, abortBound, "", cur, now))
	} else {
		t.stopParseLocked(s)
	}
	res.stateLimit = first
	return res
}

func (s *trackedSession) clearInspectionBytes() {
	if s.pairing != nil {
		s.pairing.close()
	}
	for _, d := range s.dirs {
		if d != nil {
			d.bytes.Release()
			d.frames = nil
			if d.frameLease != nil {
				d.frameLease.Release()
			}
			d.frameLease = nil
		}
	}
}

func (s *trackedSession) releaseInspection() {
	if s == nil {
		return
	}
	s.clearInspectionBytes()
	if s.memory != nil {
		s.memory.Release()
	}
	s.next.releaseInspection()
	s.next = nil
}

// stopInspection is generation retirement, not a capture rebind. It runs
// after consumers/completions join, including generations never started.
func (t *sessionTable) stopInspection() {
	t.iecAdapter.stopDelivery(t)
	t.mu.Lock()
	defer t.mu.Unlock()
	t.flushHeldCreditsLocked(0)
	for _, s := range t.sessions {
		t.dpi.EndStream(s.id)
		s.releaseInspection()
	}
	clear(t.sessions)
	clear(t.held)
	clear(t.aborts)
	t.heldTotal, t.tombstones = 0, 0
}
