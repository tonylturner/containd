// SPDX-License-Identifier: Apache-2.0

package enforce

import (
	"reflect"
	"regexp"
	"strings"
	"testing"

	"github.com/tonylturner/containd/pkg/dp/rules"
)

func TestRuleCounterNames(t *testing.T) {
	name := ruleCounterName(`a "quoted": rule/ID`)
	if !regexp.MustCompile(`^rule_[0-9a-f]{16}$`).MatchString(name) || name != ruleCounterName(`a "quoted": rule/ID`) {
		t.Fatalf("counter name %q is not a stable nft identifier", name)
	}
	if ruleCounterName("a") == ruleCounterName("b") || excessCounterName("a") != ruleCounterName("a")+"_excess" {
		t.Fatal("counter names collide")
	}
}

// Every rule gets a counter, even one that compiles to no line, and every
// line of a rule, IEC104 steering included, counts into it.
func TestCompileFirewallCountsEveryRuleLine(t *testing.T) {
	c := NewCompiler()
	c.QueueID = 100
	snap := iecSnapshot()
	snap.Firewall = append(snap.Firewall, rules.Entry{ID: "scheduled", Action: rules.ActionAllow,
		Schedule: rules.SchedulePredicate{StartTime: "01:00", EndTime: "02:00"}})
	text, err := c.CompileFirewall(snap)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range snap.Firewall {
		if !strings.Contains(text, "  counter "+ruleCounterName(e.ID)+" { }\n") {
			t.Errorf("rule %s has no counter", e.ID)
		}
	}
	forward := text[strings.Index(text, "chain forward"):]
	forward = forward[:strings.Index(forward, "\n  }\n")]
	for _, line := range strings.Split(forward, "\n")[3:] {
		if strings.Contains(line, "ct state") || strings.Contains(line, "dnat") {
			continue
		}
		if !ruleCounterStmt.MatchString(line) {
			t.Errorf("line without a rule counter: %s", line)
		}
	}
	steer := counterStmt("a-iec-allow") + " jump " + IEC104EnvelopeChain
	if strings.Count(text, steer) != 2 {
		t.Fatalf("IEC104 steering of a-iec-allow does not count both directions:\n%s", text)
	}
}

func TestCompileFirewallRejectsDuplicateRuleIDs(t *testing.T) {
	snap := &rules.Snapshot{Firewall: []rules.Entry{{ID: "x", Action: rules.ActionAllow}, {ID: "x", Action: rules.ActionDeny}}}
	if _, err := NewCompiler().CompileFirewall(snap); err == nil || !strings.Contains(err.Error(), "rule IDs must be unique") {
		t.Fatalf("err = %v", err)
	}
}

func TestRuleCountsFromListing(t *testing.T) {
	snap := &rules.Snapshot{Firewall: []rules.Entry{
		{ID: "allow", Action: rules.ActionAllow},
		{ID: "police", Action: rules.ActionRateLimit, RateLimit: &rules.RateLimit{PacketsPerSecond: 1, Burst: 1}},
	}}
	listing := `{"nftables": [{"metainfo": {"version": "1.1.1", "json_schema_version": 1}},
{"counter": {"family": "inet", "name": "` + ruleCounterName("allow") + `", "table": "containd_policy", "handle": 2, "packets": 7, "bytes": 420}},
{"counter": {"family": "inet", "name": "` + ruleCounterName("police") + `", "table": "containd_policy", "handle": 3, "packets": 50, "bytes": 3000}},
{"counter": {"family": "inet", "name": "` + excessCounterName("police") + `", "table": "containd_policy", "handle": 4, "packets": 40, "bytes": 2400}}]}`
	counters, err := parseCounters([]byte(listing))
	if err != nil {
		t.Fatal(err)
	}
	got, err := RuleCounts(snap, counters)
	if err != nil {
		t.Fatal(err)
	}
	excess := uint64(40)
	want := []RuleCount{
		{RuleID: "allow", Action: rules.ActionAllow, Packets: 7, Bytes: 420},
		{RuleID: "police", Action: rules.ActionRateLimit, Packets: 50, Bytes: 3000, ExcessDrops: &excess},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("RuleCounts = %+v, want %+v", got, want)
	}
	delete(counters, excessCounterName("police"))
	if _, err := RuleCounts(snap, counters); err == nil {
		t.Fatal("a table without the excess counter was not compiled from the snapshot")
	}
	if _, err := RuleCounts(&rules.Snapshot{Firewall: []rules.Entry{{ID: "other"}}}, counters); err == nil {
		t.Fatal("a missing rule counter was accepted")
	}
}
