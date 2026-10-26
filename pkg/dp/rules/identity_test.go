// SPDX-License-Identifier: Apache-2.0

package rules

import "testing"

// TestIdentityPredicateResolvesTowardDenial pins identity matching in every
// userspace evaluator. A flow without identities cannot decide the
// predicate: a DENY rule matches and an ALLOW rule does not. A flow that
// carries identities is matched against them.
func TestIdentityPredicateResolvesTowardDenial(t *testing.T) {
	for _, tc := range []struct {
		name   string
		action Action
		flow   []string
		match  bool
	}{
		{"allow without flow identities", ActionAllow, nil, false},
		{"allow with matching identity", ActionAllow, []string{"operator"}, true},
		{"allow with other identity", ActionAllow, []string{"guest"}, false},
		{"deny without flow identities", ActionDeny, nil, true},
		{"deny with matching identity", ActionDeny, []string{"operator"}, true},
		{"deny with other identity", ActionDeny, []string{"guest"}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			l4 := Entry{ID: "l4", Identities: []string{"operator"}, Protocols: []Protocol{{Name: "tcp", Port: "502"}}, Action: tc.action}
			ctx := EvalContext{Proto: "tcp", Port: "502", Identities: tc.flow}
			// The default is the opposite of the rule's action, so the
			// verdict tells a match apart from the fallthrough.
			def := ActionDeny
			if tc.action == ActionDeny {
				def = ActionAllow
			}
			action, matched := NewEvaluator(&Snapshot{Default: def, Firewall: []Entry{l4}}).EvaluateMatch(ctx)
			if (matched != nil) != tc.match || (tc.match && action != tc.action) || (!tc.match && action != def) {
				t.Fatalf("EvaluateMatch = %s, %v; want match %v", action, matched, tc.match)
			}
			if got := PreviewMatch(l4, ctx); got != tc.match {
				t.Fatalf("PreviewMatch = %v, want %v", got, tc.match)
			}

			iec := iecEntry("iec", tc.action, ICSPredicate{Mode: "enforce"})
			iec.Identities = []string{"operator"}
			objCtx := sessionCtx("request", iFrame(46, "control", 1, 2001, false))
			objCtx.Identities = tc.flow
			action, matched = NewEvaluator(&Snapshot{Firewall: []Entry{iec}}).EvaluateIEC104(objCtx)
			if (matched != nil) != tc.match || (tc.match && action != tc.action) || (!tc.match && action != ActionDeny) {
				t.Fatalf("EvaluateIEC104 = %s, %v; want match %v", action, matched, tc.match)
			}
		})
	}
}
