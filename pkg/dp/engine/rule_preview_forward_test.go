// SPDX-License-Identifier: Apache-2.0
package engine

import (
	"net/netip"
	"strings"
	"testing"

	"github.com/tonylturner/containd/pkg/dp/enforce"
	"github.com/tonylturner/containd/pkg/dp/events"
	"github.com/tonylturner/containd/pkg/dp/rules"
)

func TestPreviewViaUnavailableUsesCandidateForwards(t *testing.T) {
	e := &Engine{eventStore: events.NewStore(100)}
	forward := rules.ForwardMatch{Enabled: true, IngressDevices: []string{"wan0"}, Protocol: "tcp",
		ListenPort: 1502, Backend: netip.MustParseAddrPort("10.0.0.2:502")}
	e.ruleSnap.Store(&rules.Snapshot{ForwardMatches: map[string]rules.ForwardMatch{"running": forward}})
	e.eventStore.Append(events.Event{Transport: "tcp", SrcIP: "192.0.2.2", DstIP: "10.0.0.2", DstPort: 502})
	entry := rules.Entry{ID: "via", Action: rules.ActionAllow, ViaForwards: []string{"candidate"},
		ICS: rules.ICSPredicate{Protocol: "modbus", Mode: "enforce"}}
	for _, present := range []bool{true, false} {
		req := PreviewRuleRequest{Entry: entry}
		if present {
			req.ForwardMatches = map[string]rules.ForwardMatch{"candidate": forward}
		}
		got := e.PreviewCandidateRule(req)
		if got.MatchCount != 0 || got.SampleMatches == nil || len(got.SampleMatches) != 0 ||
			got.TotalEvents != 1 || got.Unavailable != "Retained events do not record which connections containd translated, so a rule limited to port forwards cannot be previewed from history." ||
			got.ICSCoverage == nil {
			t.Fatalf("present=%v response=%+v", present, got)
		}
		warned := false
		for _, w := range got.Warnings {
			warned = warned || w.Predicate == enforce.PredicateForward
		}
		if warned == present {
			t.Fatalf("candidate present=%v warnings=%+v", present, got.Warnings)
		}
	}
	// A candidate removing a running forward must warn too.
	entry.ViaForwards = []string{"running"}
	got := e.PreviewCandidateRule(PreviewRuleRequest{Entry: entry})
	if len(got.Warnings) != 1 || got.Warnings[0].Predicate != enforce.PredicateForward ||
		!strings.Contains(got.Warnings[0].Message, "no referenced forward") {
		t.Fatalf("running forward leaked into candidate: %+v", got)
	}
}
