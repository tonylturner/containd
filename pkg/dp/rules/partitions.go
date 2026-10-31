// SPDX-License-Identifier: Apache-2.0
package rules

// MonitorICS identifies observation-only ICS entries. Protocol-less rules keep
// their ordinary firewall semantics regardless of the global DPI mode.
func MonitorICS(entry Entry, globalMode string) bool {
	return entry.ICS.Protocol != "" && EffectiveMode(entry.ICS.Mode, globalMode) == "monitor"
}

// EvaluateEnforcing uses the compiled decision partition, excluding monitor
// predicates. The regular firewall default still applies.
func (e *Evaluator) EvaluateEnforcing(ctx EvalContext) (Action, *Entry) {
	for _, i := range e.enforcing {
		if ce := &e.compiled[i]; ce.matches(ctx) {
			return ce.Action, &ce.Entry
		}
	}
	if e.snapshot != nil && e.snapshot.Default == ActionAllow {
		return ActionAllow, nil
	}
	return ActionDeny, nil
}

// EvaluateIEC104Enforcing judges only the enforcing IEC partition. Envelope
// defaults deny; a monitor ALLOW cannot satisfy that default.
func (e *Evaluator) EvaluateIEC104Enforcing(ctx EvalContext) (Action, *Entry) {
	for _, i := range e.enforcing {
		if ce := &e.compiled[i]; ce.iec != nil && ce.matches(ctx) {
			return ce.Action, &ce.Entry
		}
	}
	return ActionDeny, nil
}

// MonitorMatches shares the exact compiled predicates with the enforcing
// partition and visits every matching monitor rule, not just the first winner.
func (e *Evaluator) MonitorMatches(ctx EvalContext) []*Entry {
	var out []*Entry
	for _, i := range e.monitor {
		if ce := &e.compiled[i]; ce.matches(ctx) {
			out = append(out, &ce.Entry)
		}
	}
	return out
}

// IEC104Scope returns a matching L3/L4 envelope owner, preferring enforce.
// Payload, identity and schedule predicates do not narrow the envelope.
func (e *Evaluator) IEC104Scope(ctx EvalContext, globalMode string) *Entry {
	var observed *Entry
	for i := range e.compiled {
		ce := &e.compiled[i]
		if ce.iec == nil || !matchZones(&ce.Entry, ctx) || !matchCIDRs(ce, ctx) || !matchProtoCompiled(ce, ctx) {
			continue
		}
		if EffectiveMode(ce.ICS.Mode, globalMode) == "enforce" {
			return &ce.Entry
		}
		if observed == nil {
			observed = &ce.Entry
		}
	}
	return observed
}
