// SPDX-License-Identifier: Apache-2.0

package enforce

import (
	"reflect"
	"strings"
	"testing"

	"github.com/tonylturner/containd/pkg/dp/rules"
)

// TestUnenforcedPredicatesResolveTowardDenial pins how identity and
// schedule predicates compile: a rule decided by nftables cannot honour
// them, so its ALLOW is not emitted and its DENY drops unconditionally. A
// rule queued to the engine keeps its queue verdict; the engine evaluates
// schedules but not identities.
func TestUnenforcedPredicatesResolveTowardDenial(t *testing.T) {
	predicates := map[string]func(*rules.Entry){
		"identity": func(e *rules.Entry) { e.Identities = []string{"operator"} },
		"schedule": func(e *rules.Entry) {
			e.Schedule = rules.SchedulePredicate{DaysOfWeek: []string{"Saturday"}, StartTime: "02:00", EndTime: "06:00"}
		},
	}
	for _, tc := range []struct {
		name    string
		ics     string
		queueID int
		action  rules.Action
		line    string // "" when no line may be emitted
		warn    map[string]string
	}{
		{"L4 allow", "", 0, rules.ActionAllow, "", map[string]string{
			"identity": "identity predicates are not enforced yet; ALLOW rule inactive",
			"schedule": "schedules are enforced only on ICS rules inspected through NFQUEUE; ALLOW rule inactive"}},
		{"L4 deny", "", 0, rules.ActionDeny, "tcp dport 502 drop", map[string]string{
			"identity": "identity predicates are not enforced yet; DENY rule applies as if the identity always matched",
			"schedule": "schedules are enforced only on ICS rules inspected through NFQUEUE; DENY rule applies as if the schedule always matched"}},
		{"L4 allow with queue", "", 100, rules.ActionAllow, "", map[string]string{
			"identity": "identity predicates are not enforced yet; ALLOW rule inactive",
			"schedule": "schedules are enforced only on ICS rules inspected through NFQUEUE; ALLOW rule inactive"}},
		{"ICS allow without queue", "modbus", 0, rules.ActionAllow, "", map[string]string{
			"identity": "identity predicates are not enforced yet; ALLOW rule inactive",
			"schedule": "schedules are enforced only on ICS rules inspected through NFQUEUE; ALLOW rule inactive"}},
		{"ICS deny without queue", "modbus", 0, rules.ActionDeny, "tcp dport 502 drop", map[string]string{
			"identity": "identity predicates are not enforced yet; DENY rule applies as if the identity always matched",
			"schedule": "schedules are enforced only on ICS rules inspected through NFQUEUE; DENY rule applies as if the schedule always matched"}},
		{"ICS allow queued", "modbus", 100, rules.ActionAllow, "tcp dport 502 queue num 100", map[string]string{
			"identity": "identity predicates are not enforced yet; ALLOW rule inactive"}},
		{"ICS deny queued", "modbus", 100, rules.ActionDeny, "tcp dport 502 queue num 100", map[string]string{
			"identity": "identity predicates are not enforced yet; DENY rule applies as if the identity always matched"}},
	} {
		for pred, set := range predicates {
			t.Run(tc.name+"/"+pred, func(t *testing.T) {
				e := rules.Entry{ID: "r1", Action: tc.action, Protocols: []rules.Protocol{{Name: "tcp", Port: "502"}},
					ICS: rules.ICSPredicate{Protocol: tc.ics}}
				set(&e)
				lines, err := compileEntry(e, nil, tc.queueID, 0)
				if err != nil {
					t.Fatal(err)
				}
				if (tc.line == "" && len(lines) != 0) || (tc.line != "" && !reflect.DeepEqual(lines, []string{tc.line})) {
					t.Fatalf("lines = %q, want %q", lines, tc.line)
				}
				c := NewCompiler()
				c.QueueID = tc.queueID
				var want []RuleWarning
				if msg, ok := tc.warn[pred]; ok {
					want = []RuleWarning{{RuleID: "r1", Predicate: UnenforcedPredicate(pred), Action: tc.action, Message: msg}}
				}
				if got := c.RuleWarnings(&rules.Snapshot{Firewall: []rules.Entry{e}}); !reflect.DeepEqual(got, want) {
					t.Fatalf("warnings = %+v, want %+v", got, want)
				}
			})
		}
	}
}

// TestCompileFirewallOmitsScheduledAllow compiles a maintenance-window
// style policy: the scheduled zone ALLOW must not open the zone pair, and
// the warnings name each predicate of each affected rule in rule order.
func TestCompileFirewallOmitsScheduledAllow(t *testing.T) {
	window := rules.SchedulePredicate{DaysOfWeek: []string{"Saturday", "Sunday"}, StartTime: "02:00", EndTime: "06:00", Timezone: "America/New_York"}
	snap := &rules.Snapshot{
		Default:    rules.ActionDeny,
		ZoneIfaces: map[string][]string{"l3": {"eth3"}, "l1": {"eth1"}},
		Firewall: []rules.Entry{
			{ID: "maint-l3-to-l1", SourceZones: []string{"l3"}, DestZones: []string{"l1"}, Action: rules.ActionAllow, Schedule: window},
			{ID: "deny-guests", SourceZones: []string{"l3"}, Identities: []string{"guest"}, Action: rules.ActionDeny, Schedule: window},
			{ID: "web", Protocols: []rules.Protocol{{Name: "tcp", Port: "443"}}, Action: rules.ActionAllow},
		},
	}
	c := NewCompiler()
	ruleset, err := c.CompileFirewall(snap)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(ruleset, `oifname { "eth1" }`) {
		t.Fatalf("scheduled ALLOW compiled to an always-on accept:\n%s", ruleset)
	}
	for _, want := range []string{`iifname { "eth3" } drop`, "tcp dport 443 accept"} {
		if !strings.Contains(ruleset, want) {
			t.Fatalf("missing %q:\n%s", want, ruleset)
		}
	}
	var got []string
	for _, w := range c.RuleWarnings(snap) {
		got = append(got, w.RuleID+"/"+string(w.Predicate))
	}
	if want := []string{"deny-guests/identity", "deny-guests/schedule", "maint-l3-to-l1/schedule"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("warnings = %q, want %q", got, want)
	}
}
