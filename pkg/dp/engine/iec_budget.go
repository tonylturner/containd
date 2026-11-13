// SPDX-License-Identifier: Apache-2.0
package engine

import (
	"net/netip"
	"time"

	"github.com/tonylturner/containd/pkg/dp/dpi"
	"github.com/tonylturner/containd/pkg/dp/flow"
	"github.com/tonylturner/containd/pkg/dp/limits"
	"github.com/tonylturner/containd/pkg/dp/rules"
)

func (t *iecTable) allocateSessionLocked(client, server netip.AddrPort, ctx rules.EvalContext, mode string, state *flow.State, now time.Time) *iecSession {
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
	return &iecSession{memory: memory, id: t.newID(), flow: retainedIECState(state),
		client: client, server: server, ctx: ctx, mode: mode, lastSeen: now,
		held: make([]*heldPacket, 0, iecMaxHeldPerSession)}
}

func (t *iecTable) admissionLimitLocked(mode string) iecResult {
	t.ledger.Record(limits.TableInspection, limits.ReasonRefused, limits.Mode(mode))
	res := accepted(reasonIECUntracked)
	if mode == "enforce" {
		t.countAbort(abortBound)
		res = dropped("state_limit")
	}
	res.stateLimit = true
	return res
}

func (t *iecTable) allocateDirLocked(s *iecSession, dir int, isn uint32) error {
	stream, err := flow.NewBudgetedByteStream(iecStreamMaxBytes, iecStreamMaxSegments, t.resources, s.mode == "enforce")
	if err != nil {
		return err
	}
	if old := s.dirs[dir]; old != nil {
		old.bytes.Release()
		old.frames = nil
		s.memory.Refund(old.frameCharge)
	}
	s.dirs[dir] = &iecDir{hasISN: true, isn: isn, seq: flow.NewSeqSpace(isn), bytes: stream}
	return nil
}

func (t *iecTable) inspectionLimitLocked(s *iecSession, cur *heldPacket, now time.Time) iecResult {
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

func (s *iecSession) clearInspectionBytes() {
	for _, d := range s.dirs {
		if d != nil {
			d.bytes.Release()
			d.frames = nil
			if s.memory != nil {
				s.memory.Refund(d.frameCharge)
			}
			d.frameCharge = 0
		}
	}
}

func (s *iecSession) releaseInspection() {
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
func (t *iecTable) stopInspection() {
	t.stopInventory()
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

func (s *iecSession) retainFrames(d *iecDir, frames []dpi.DecodedFrame) bool {
	if len(frames) == 0 {
		return true
	}
	size := (len(d.frames) + len(frames)) * 16
	if !s.memory.Reserve(size) {
		return false
	}
	replacement := make([]iecFrame, len(d.frames)+len(frames))
	copy(replacement, d.frames)
	for i, f := range frames {
		replacement[len(d.frames)+i] = iecFrame{start: f.Start, end: f.End}
	}
	old := d.frameCharge
	d.frames, d.frameCharge = replacement, size
	s.memory.Refund(old)
	return true
}
