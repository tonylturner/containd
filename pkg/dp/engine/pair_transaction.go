// SPDX-License-Identifier: Apache-2.0
package engine

import (
	"slices"
	"time"

	"github.com/tonylturner/containd/pkg/dp/dpi"
	"github.com/tonylturner/containd/pkg/dp/limits"
	"github.com/tonylturner/containd/pkg/dp/rules"
)

// Operations are owned by existing physical frame records. They have no grant
// state until the gate releases every carrying token under the session lock.
type pairOperation struct {
	frame    dpi.DecodedFrame
	dir      dpi.StreamDir
	permit   requestPermit
	nonAdmit bool
}
type pairJournal[K protocolPairKey, S any] struct {
	created, removed []*pairGrant[K, S]
	evicted          int
}

func releasePairGrant[K protocolPairKey, S any](g *pairGrant[K, S]) {
	g.lease.Release()
	if g.contextLease != nil {
		g.contextLease.Release()
	}
}
func (b *pairLedger[K, S]) retain(f dpi.DecodedFrame, dir dpi.StreamDir) (dpi.DecodedFrame, *limits.Lease, pairReason) {
	_, _, shape, why := b.adapter.Classify(f, dir)
	if why != pairOK {
		return dpi.DecodedFrame{}, nil, why
	}
	lease, ok := b.resources.Budget.Reserve(b.class(), limits.CategoryPairing, 256+b.adapter.Charge(shape)+int64(len(f.Coverage))*16)
	if !ok {
		return dpi.DecodedFrame{}, nil, stateLimit
	}
	return dpi.DecodedFrame{Start: f.Start, End: f.End, Coverage: slices.Clone(f.Coverage), Unit: b.adapter.Unit(b.adapter.Copy(shape))}, lease, pairOK
}

// A bounded undo journal covers the complete release plan, not a second ledger
// or a pending grant phase. No credit is refunded until commit; a failed plan
// restores cursors, grants, markers and accounting before any token is released.
func (b *pairLedger[K, S]) transact(ops []pairOperation, now time.Time) pairReason {
	if len(ops) == 0 {
		return pairOK
	}
	n := int64(len(b.grants)+len(ops)+pairSessionCap) * 256
	credit, ok := b.resources.Budget.Reserve(b.class(), limits.CategoryPairing, n)
	if !ok {
		return stateLimit
	}
	defer credit.Release()
	originalBacking := b.grants
	original := slices.Clone(originalBacking)
	states := make([]pairProgress, len(original))
	for i, g := range original {
		states[i] = g.State
	}
	markerBacking := b.markers
	markers := slices.Clone(markerBacking)
	oldLease := b.markerLease
	total := 0
	if b.total != nil {
		total = *b.total
	}
	journal := &pairJournal[K, S]{created: make([]*pairGrant[K, S], 0, len(ops)), removed: make([]*pairGrant[K, S], 0, len(ops)+len(original))}
	b.journal = journal
	why := pairOK
	for _, op := range ops {
		if op.nonAdmit {
			class, reason := b.inspect(op.frame, op.dir, now)
			if class == rules.ClassSolicited && reason != pairOK {
				why = reason
				break
			}
			continue
		}
		if why = b.apply(op.frame, op.dir, op.permit, now); why != pairOK {
			break
		}
	}
	b.journal = nil
	if why == pairOK {
		for _, g := range journal.removed {
			releasePairGrant(g)
		}
		for range journal.evicted {
			b.resources.Ledger.Record(limits.TableInspection, limits.ReasonEvicted, limits.Mode(b.mode()))
		}
		return pairOK
	}
	for _, g := range journal.created {
		releasePairGrant(g)
	}
	// Restore the retained, already charged backing stores, not the transient
	// snapshot whose reservation is refunded on return.
	clear(b.grants)
	b.grants = originalBacking
	copy(b.grants, original)
	for i, g := range original {
		g.State = states[i]
	}
	b.markers = markerBacking
	copy(b.markers, markers)
	if oldLease == nil && b.markerLease != nil {
		b.markerLease.Release()
	}
	b.markerLease = oldLease
	if b.total != nil {
		*b.total = total
	}
	return why
}
