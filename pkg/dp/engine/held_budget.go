// SPDX-License-Identifier: Apache-2.0
package engine

import (
	"errors"

	"github.com/tonylturner/containd/pkg/dp/capture"
	"github.com/tonylturner/containd/pkg/dp/limits"
)

// Settlement owns credits beyond the held list: returning a resolution does
// not mean its verdict has been submitted. All access is under the session lock.
type heldCredit struct {
	lease    *limits.Lease
	protocol string
	session  *trackedSession
	verdict  capture.Verdict
}

func heldProtocolShare(protocol string) int {
	switch protocol {
	case "modbus", "dnp3":
		return 80
	case "iec104":
		return 96
	default:
		return 0
	}
}

func (t *sessionTable) holdCreditLocked(tok capture.Token, payload int, enforcing bool, protocol string) bool {
	if t.settlements[tok] != nil {
		return true
	}
	if payload < 0 || len(t.settlements) >= sessionMaxHeldGlobal {
		return false
	}
	count := 0
	for _, credit := range t.settlements {
		if credit.protocol == protocol {
			count++
		}
	}
	if count >= heldProtocolShare(protocol) {
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
	t.settlements[tok] = &heldCredit{lease: lease, protocol: protocol}
	return true
}

func (t *sessionTable) releaseHeldCreditLocked(tok capture.Token) {
	if credit := t.settlements[tok]; credit != nil {
		delete(t.settlements, tok)
		credit.lease.Release()
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

// A rejection can race a submission already removed from capture's token map.
// Only a successful send or explicit disappearance proof refunds residency.
func residencySettled(err error) bool {
	return err == nil || errors.Is(err, capture.ErrTokenFlushed) || errors.Is(err, capture.ErrQueueClosed) || errors.Is(err, capture.ErrStaleToken)
}
