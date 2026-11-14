// SPDX-License-Identifier: Apache-2.0
package engine

import (
	"time"

	"github.com/tonylturner/containd/pkg/dp/limits"
	"github.com/tonylturner/containd/pkg/dp/rules"
)

// A publication refreshes request policy inputs exactly once. Reply processing
// never re-evaluates identities or schedules: authorization is bounded by the
// request's original absolute expiry, not by continuously changing inputs.
func (b *pairLedger[K, S]) reauthorize(policy *compiledRules, base rules.EvalContext, now time.Time) pairReason {
	b.expire(now)
	if policy == nil {
		return pairOK
	}
	for i := len(b.grants) - 1; i >= 0; i-- {
		g := b.grants[i]
		if g.Permit.Epoch == policy.epoch {
			continue
		}
		if g.autonomous {
			g.Permit.Epoch = policy.epoch
			continue
		}
		// Contexts are temporary references into immutable snapshots here. Reserve
		// replacement capacity before copying any retained identity/object storage.
		allowed := len(g.Permit.Contexts) > 0
		size := int64(0)
		for _, old := range g.Permit.Contexts {
			ctx := base
			ctx.ICS = old.ICS
			ctx.Now = now
			size += pairContextsCharge([]rules.EvalContext{ctx})
			action, entry := policy.evaluator.EvaluateMessage(ctx, false)
			if ctx.ICS != nil && ctx.ICS.Protocol == iecProtocol {
				action, entry = policy.evaluator.EvaluateIEC104Enforcing(ctx)
			}
			if b.observe {
				entry = policy.evaluator.AnyMatch(ctx)
				action = rules.ActionDeny
				if entry != nil {
					action = entry.Action
				}
			}
			if action != rules.ActionAllow || entry == nil || ctx.ICS == nil || entry.ICS.Protocol != ctx.ICS.Protocol {
				allowed = false
			}
		}
		if !allowed {
			b.mark(g.Key, pairExpired)
			b.remove(i)
			continue
		}
		lease, ok := b.resources.Budget.Reserve(b.class(), limits.CategoryPairing, size)
		if !ok {
			b.resources.Ledger.Record(limits.TableInspection, limits.ReasonRefused, limits.Mode(b.mode()))
			b.mark(g.Key, pairExpired)
			b.remove(i)
			return stateLimit
		}
		contexts := make([]rules.EvalContext, len(g.Permit.Contexts))
		for j, old := range g.Permit.Contexts {
			contexts[j] = base
			contexts[j].ICS = old.ICS
			contexts[j].Now = now
		}
		owned := pairCopyContexts(contexts)
		if g.contextLease != nil {
			g.contextLease.Release()
		} else {
			g.lease.Shrink(pairContextsCharge(g.Permit.Contexts))
		}
		g.contextLease = lease
		g.Permit = requestPermit{Epoch: policy.epoch, Contexts: owned}
	}
	return pairOK
}
