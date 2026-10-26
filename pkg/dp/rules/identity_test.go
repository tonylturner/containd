// SPDX-License-Identifier: Apache-2.0

package rules

import (
	"net"
	"slices"
	"testing"
)

// TestIdentityPredicateMatchesBoundOpeners pins identity matching in every
// userspace evaluator: the predicate holds when the opener carries any of
// the rule's labels, compared exactly. An opener without identities matches
// no identity rule, whatever its action.
func TestIdentityPredicateMatchesBoundOpeners(t *testing.T) {
	for _, tc := range []struct {
		name   string
		action Action
		flow   []string
		match  bool
	}{
		{"allow without flow identities", ActionAllow, nil, false},
		{"allow with matching identity", ActionAllow, []string{"guest", "operator"}, true},
		{"allow with other identity", ActionAllow, []string{"guest"}, false},
		{"allow is case-sensitive", ActionAllow, []string{"Operator"}, false},
		{"deny without flow identities", ActionDeny, nil, false},
		{"deny with matching identity", ActionDeny, []string{"operator"}, true},
		{"deny with other identity", ActionDeny, []string{"guest"}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			l4 := Entry{ID: "l4", Identities: []string{"operator", "engineer"}, Protocols: []Protocol{{Name: "tcp", Port: "502"}}, Action: tc.action}
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

func TestSnapshotIdentitiesOf(t *testing.T) {
	snap := &Snapshot{IdentityBindings: []IdentityBinding{
		{IP: "10.0.0.5", Identities: []string{"operator"}},
		{IP: "10.0.0.20", Identities: []string{"engineer", "operator"}},
		{IP: "2001:db8::7", Identities: []string{"vendor"}},
	}}
	for _, tc := range []struct {
		ip   string
		want []string
	}{
		{"10.0.0.5", []string{"operator"}},
		{"10.0.0.20", []string{"engineer", "operator"}},
		{"::ffff:10.0.0.20", []string{"engineer", "operator"}},
		{"2001:db8::7", []string{"vendor"}},
		{"10.0.0.6", nil},
		{"2001:db8::8", nil},
		{"192.0.2.1", nil},
	} {
		if got := snap.IdentitiesOf(net.ParseIP(tc.ip)); !slices.Equal(got, tc.want) {
			t.Errorf("IdentitiesOf(%s) = %v, want %v", tc.ip, got, tc.want)
		}
	}
	var none *Snapshot
	if got := none.IdentitiesOf(net.ParseIP("10.0.0.5")); got != nil {
		t.Fatalf("nil snapshot bound %v", got)
	}
	if got := snap.IdentitiesOf(nil); got != nil {
		t.Fatalf("nil address bound %v", got)
	}
}
