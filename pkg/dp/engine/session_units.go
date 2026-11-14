// SPDX-License-Identifier: Apache-2.0
package engine

import (
	"time"

	"github.com/tonylturner/containd/pkg/dp/dpi"
	"github.com/tonylturner/containd/pkg/dp/ics/project"
	"github.com/tonylturner/containd/pkg/dp/limits"
	"github.com/tonylturner/containd/pkg/dp/rules"
)

// Retain decoder authority on the physical completion record already owned by
// the range gate. There is no parallel message queue or pending grant state.
func (t *sessionTable) prepareUnitsLocked(s *trackedSession, dir int, frames []dpi.DecodedFrame, now time.Time, res *sessionResult) pairReason {
	if s.pairing == nil {
		return pairUnsupported
	}
	d := s.dirs[dir]
	compiled := t.ruleOwner.current.Load()
	if compiled == nil {
		return pairUnknown
	}
	failure := pairOK
	for _, f := range frames {
		if f.Pending {
			continue
		}
		class, why := s.pairing.inspect(f, dpiDir(dir), now)
		permit, nonAdmit, policyWhy := t.unitPolicyLocked(s, dir, f, class, why == pairOK, compiled, now, res)
		if why == pairUnsupported {
			// An unknown class cannot match an enforcing ALLOW. Preserve the
			// typed unsupported cause, not that secondary policy mismatch.
			policyWhy = why
		}
		if policyWhy != pairOK {
			stampPairing(f.Events, class, policyWhy)
			if failure == pairOK {
				failure = policyWhy
			}
			continue
		}
		if why != pairOK {
			stampPairing(f.Events, class, why)
			if failure == pairOK {
				failure = why
			}
			continue
		}
		stampPairing(f.Events, class, why)
		if failure != pairOK {
			continue
		}
		owned, lease, why := s.pairing.retain(f, dpiDir(dir))
		if why != pairOK {
			return why
		}
		contexts, ok := t.resources.Budget.Reserve(limits.ClassEnforce, limits.CategoryPairing, pairContextsCharge(permit.Contexts))
		if !ok {
			lease.Release()
			return stateLimit
		}
		permit.Contexts = pairCopyContexts(permit.Contexts)
		op := &pairOperation{frame: owned, dir: dpiDir(dir), permit: permit, nonAdmit: nonAdmit}
		for i := range d.frames {
			p := &d.frames[i]
			if p.start == f.Start && p.end == f.End {
				p.operation, p.operationLease, p.contextLease = op, lease, contexts
			}
			if nonAdmit && frameCarries(owned, p.start, p.end) {
				p.nonAdmit = true
			}
		}
	}
	return failure
}

func (t *sessionTable) unitPolicyLocked(s *trackedSession, dir int, f dpi.DecodedFrame, class rules.MessageClass, paired bool, compiled *compiledRules, now time.Time, res *sessionResult) (requestPermit, bool, pairReason) {
	if sessionProtocol(s.flow) != iecProtocol {
		return t.genericUnitPolicyLocked(s, dir, f, class, paired, compiled, now, res)
	}
	permit := requestPermit{Epoch: compiled.epoch}
	objects, err := project.UnitObjects(f.Unit, class, dpiDir(dir))
	if err != nil || len(objects) == 0 {
		// Unsupported content is never authorized by its event projection.
		// Retain its diagnostic rule/conformance evidence, then fail closed.
		j := t.iecAdapter.judgeLocked(t, s, f.Events, now)
		res.acts.events = append(res.acts.events, j.events...)
		res.findings = append(res.findings, j.findings...)
		if res.trigger == "" {
			res.trigger = j.trigger
		}
		return permit, false, pairUnsupported
	}
	nonAdmit := false
	why := pairOK
	seen := map[string]map[string]bool{}
	j := iecJudgement{}
	for i := range objects {
		ctx := s.ctx
		ctx.Now, ctx.ICS = now, &objects[i]
		var ev dpi.Event
		if i < len(f.Events) {
			ev = f.Events[i]
		}
		if hasInspectionFindings(ev) {
			ctx.ICS.IEC104.SafeRead = false
		}
		d, entry := t.decideContextLocked(&s.iecSession, ev, ctx)
		if i < len(f.Events) {
			t.judgeDecisionLocked(t, s, ev, ctx, d, seen, &j, now)
		}
		allowed := d.decision == decisionAllow
		explicit := entry != nil && entry.ICS.Protocol == ctx.ICS.Protocol
		switch {
		case class == rules.ClassAutonomous && (!allowed || !explicit || entry.ICS.MessageClass != string(class)):
			why = autonomousRequired
		case class == rules.ClassSession && (!allowed || !explicit || entry.ICS.MessageClass != string(class)):
			why = sessionRequired
		case !allowed:
			why = pairMismatch
		case class == rules.ClassRequest && !explicit:
			nonAdmit = true
		}
		permit.Contexts = append(permit.Contexts, ctx)
	}
	res.acts.events = append(res.acts.events, j.events...)
	res.findings = append(res.findings, j.findings...)
	if res.trigger == "" {
		res.trigger = j.trigger
	}
	return permit, nonAdmit, why
}

func frameCarries(f dpi.DecodedFrame, start, end int64) bool {
	if f.Coverage == nil {
		return f.Start < end && start < f.End
	}
	for _, r := range f.Coverage {
		if r.Start < end && start < r.End {
			return true
		}
	}
	return false
}

// A unit commits exactly once, only after all its carrying tokens are
// releasable. A non-admitting coalesced sibling prevents the whole packet from
// minting permission, including for a request whose own rule allowed it.
func (t *sessionTable) commitUnitsLocked(s *trackedSession, dir int, cur *heldPacket, now time.Time) pairReason {
	d := s.dirs[dir]
	n := 0
	for i := range d.frames {
		if d.frames[i].operation != nil {
			n++
		}
	}
	if n == 0 {
		return pairOK
	}
	credit, ok := t.resources.Budget.Reserve(limits.ClassEnforce, limits.CategoryPairing, int64(n)*256)
	if !ok {
		return stateLimit
	}
	defer credit.Release()
	ops := make([]pairOperation, 0, n)
	indices := make([]int, 0, n)
	for i := range d.frames {
		op := d.frames[i].operation
		if op == nil {
			continue
		}
		ready, nonAdmit := true, op.nonAdmit
		check := func(h *heldPacket) {
			if h.dir != dir || !frameCarries(op.frame, h.off, h.end) {
				return
			}
			if !d.covered(h.off, h.end) {
				ready = false
			}
			nonAdmit = nonAdmit || d.nonAdmitting(h.off, h.end)
		}
		for _, h := range s.held {
			check(h)
		}
		check(cur)
		if !ready {
			continue
		}
		copy := *op
		copy.nonAdmit = nonAdmit
		ops = append(ops, copy)
		indices = append(indices, i)
	}
	if why := s.pairing.transact(ops, now); why != pairOK {
		return why
	}
	for _, i := range indices {
		d.frames[i].releaseOperation()
	}
	return pairOK
}

func (f *sessionFrame) releaseOperation() {
	if f.operationLease != nil {
		f.operationLease.Release()
	}
	if f.contextLease != nil {
		f.contextLease.Release()
	}
	f.operation, f.operationLease, f.contextLease = nil, nil, nil
}
