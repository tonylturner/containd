// SPDX-License-Identifier: Apache-2.0
package rules

// ProtocolEnvelope is the L3/L4 inspection union for one supported service.
// Payload, identity and schedule predicates cannot remove inspection coverage.
// An overlapping enforce rule always dominates an observation-only scope.
func (e *Evaluator) ProtocolEnvelope(ctx EvalContext, protocol, globalMode string) (bool, string) {
	observed := false
	for i := range e.compiled {
		ce := &e.compiled[i]
		if ce.ICS.Protocol != protocol || !e.TransportScopeMatch(i, ctx) {
			continue
		}
		if EffectiveMode(ce.ICS.Mode, globalMode) == "enforce" {
			return true, "enforce"
		}
		observed = true
	}
	if observed {
		return true, "monitor"
	}
	return false, ""
}
