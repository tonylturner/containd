// SPDX-License-Identifier: Apache-2.0
package events

import (
	"net/url"
	"testing"
)

func TestRuleModeQuery(t *testing.T) {
	q, filtered, err := ParseQuery(url.Values{"ruleId": {"Trial"}, "mode": {"monitor"}, "kind": {"ics.decision"}})
	if err != nil || !filtered {
		t.Fatal(q, err)
	}
	again, _, err := ParseQuery(q.Values())
	if err != nil || again.RuleID != q.RuleID || again.Mode != q.Mode {
		t.Fatal(again, err)
	}
	for _, tc := range []struct {
		id, mode, kind string
		want           bool
	}{{"Trial", "monitor", "ics.decision", true}, {"trial", "monitor", "ics.decision", false}, {"Trial", "enforce", "ics.decision", false}, {"Trial", "monitor", "firewall.rule.hit", false}} {
		if got := q.Matches(Event{Kind: tc.kind, Attributes: map[string]any{"ruleId": tc.id, "mode": tc.mode}}); got != tc.want {
			t.Fatal(tc, got)
		}
	}
	if _, _, err := ParseQuery(url.Values{"mode": {"learn"}}); err == nil {
		t.Fatal("legacy mode query accepted")
	}
}
