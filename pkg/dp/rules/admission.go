// SPDX-License-Identifier: Apache-2.0
package rules

// TransportScopeMatch tests a rule's zones, client/backend CIDRs, transport,
// service port and via. Identity, schedule and application selectors deliberately
// do not narrow inspection or conditional-rematch scope unions.
func (e *Evaluator) TransportScopeMatch(i int, ctx EvalContext) bool {
	ce := &e.compiled[i]
	return matchZones(&ce.Entry, ctx) && matchCIDRs(ce, ctx) && matchProtoCompiled(ce, ctx) && ce.matchVia(ctx)
}

// EvaluateTransport evaluates S2 in configured enforcing-terminal order.
// With inspection enabled, every enforcing ICS action admits transport for
// inspection, retaining its winning Entry (and original Action). It does not
// decide any decoded message or override a prior safety veto. With inspection
// disabled, ICS terminals act as plain transport actions.
func (e *Evaluator) EvaluateTransport(ctx EvalContext, inspection bool) (Action, *Entry) {
	for _, i := range e.enforcing {
		ce := &e.compiled[i]
		if !e.TransportScopeMatch(i, ctx) || !matchIdentities(ce.Entry, ctx) || !matchSchedule(ce, ctx) {
			continue
		}
		if inspection && ce.ICS.Protocol != "" {
			return ActionAllow, &ce.Entry
		}
		return ce.Action, &ce.Entry
	}
	if e.snapshot != nil && e.snapshot.Default == ActionAllow {
		return ActionAllow, nil
	}
	return ActionDeny, nil
}

// EvaluateMessage is the single full-context S4 evaluation for generic decoded
// contexts. A captured reply suppresses only an unmatched ordinary default;
// explicit terminal decisions still apply. IEC callers use EvaluateIEC104Enforcing.
func (e *Evaluator) EvaluateMessage(ctx EvalContext, reply bool) (Action, *Entry) {
	action, entry := e.EvaluateEnforcing(ctx)
	if reply && entry == nil {
		return ActionAllow, nil
	}
	return action, entry
}
