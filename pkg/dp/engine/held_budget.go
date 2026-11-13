// SPDX-License-Identifier: Apache-2.0
package engine

import (
	"github.com/tonylturner/containd/pkg/dp/capture"
	"github.com/tonylturner/containd/pkg/dp/limits"
)

// Settlement owns credits beyond the held list: returning a resolution does
// not mean its verdict has been submitted. All access is under the session lock.
func (t *sessionTable) holdCreditLocked(tok capture.Token, payload int, enforcing bool) bool {
	if t.settlements[tok] != nil {
		return true
	}
	if payload < 0 || len(t.settlements) >= sessionMaxHeldGlobal {
		return false
	}
	class := limits.ClassObserve
	if enforcing {
		class = limits.ClassEnforce
	}
	n := int64(payload) + limits.HeldPacketHeaderAllowanceBytes + limits.HeldTokenMetadataBytes
	lease, ok := t.resources.Budget.Reserve(class, limits.CategoryHeld, n)
	if !ok {
		return false
	}
	t.settlements[tok] = lease
	return true
}

func (t *sessionTable) releaseHeldCreditLocked(tok capture.Token) {
	if lease := t.settlements[tok]; lease != nil {
		delete(t.settlements, tok)
		lease.Release()
	}
}

func (t *sessionTable) flushHeldCreditsLocked(generation uint64) {
	for tok := range t.settlements {
		if generation == 0 || tok.Generation() == generation {
			t.releaseHeldCreditLocked(tok)
		}
	}
}

func (t *sessionTable) flushHeldCredits() {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.flushHeldCreditsLocked(0)
}
