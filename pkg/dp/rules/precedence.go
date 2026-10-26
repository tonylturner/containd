// SPDX-License-Identifier: Apache-2.0

package rules

import "sort"

// Decides reports whether a rule with action a decides a packet: ALLOW,
// DENY and RESET do. RATE_LIMIT and TAG are effects and never decide.
func (a Action) Decides() bool {
	return a == ActionAllow || a == ActionDeny || a == ActionReset
}

// DecisionOrder returns the indexes of the deciding entries in the order
// the dataplane decides them: every ALLOW by rule ID, then every DENY and
// RESET by rule ID. A packet is allowed if any ALLOW matches; otherwise
// the first matching DENY or RESET decides it; otherwise the default
// applies. The first match in this order is the reported rule, in nftables
// and in the engine alike.
func DecisionOrder(entries []Entry) []int {
	out := make([]int, 0, len(entries))
	for i, e := range entries {
		if e.Action.Decides() {
			out = append(out, i)
		}
	}
	sort.SliceStable(out, func(i, j int) bool {
		a, b := entries[out[i]], entries[out[j]]
		if (a.Action == ActionAllow) != (b.Action == ActionAllow) {
			return a.Action == ActionAllow
		}
		return a.ID < b.ID
	})
	return out
}

// matches reports whether every predicate of the entry holds for ctx.
func (ce *compiledEntry) matches(ctx EvalContext) bool {
	return matchZones(ce.Entry, ctx) && matchCIDRs(ce.Entry, ctx) && matchProtoCompiled(ce, ctx) &&
		matchIdentities(ce.Entry, ctx) && matchICSCompiled(ce, ctx) && matchSchedule(ce.Entry, ctx)
}

// AnyMatch returns the first entry, in snapshot order and whatever its
// action, whose predicates all hold for ctx; nil when none does. The rule
// impact preview counts one rule's matches with it, effects included.
func (e *Evaluator) AnyMatch(ctx EvalContext) *Entry {
	for i := range e.compiled {
		if ce := &e.compiled[i]; ce.matches(ctx) {
			return &ce.Entry
		}
	}
	return nil
}
