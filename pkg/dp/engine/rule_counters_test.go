// SPDX-License-Identifier: Apache-2.0

package engine

import (
	"context"
	"errors"
	"regexp"
	"testing"

	"github.com/tonylturner/containd/pkg/dp/enforce"
	"github.com/tonylturner/containd/pkg/dp/rules"
)

// countingApplier records the applied ruleset and reports each counter it
// declares with a distinct value: the n-th declared counter has n packets.
type countingApplier struct {
	recordingApplier
	table string
}

var counterDecl = regexp.MustCompile(`(?m)^  counter (\S+) \{ \}$`)

func (a *countingApplier) ReadCounters(_ context.Context, table string) (map[string]enforce.CounterValue, error) {
	a.table = table
	out := map[string]enforce.CounterValue{}
	for i, m := range counterDecl.FindAllStringSubmatch(a.ruleset, -1) {
		out[m[1]] = enforce.CounterValue{Packets: uint64(i + 1), Bytes: uint64(100 * (i + 1))}
	}
	return out, nil
}

func TestRuleCountersOfTheAppliedRuleset(t *testing.T) {
	applier := &countingApplier{}
	e, err := New(Config{Enforce: EnforceConfig{Enabled: true, TableName: "lab", Applier: applier}})
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	if _, err := e.RuleCounters(ctx); !errors.Is(err, ErrRuleCountersUnavailable) {
		t.Fatalf("before any apply: %v", err)
	}
	snap := rules.Snapshot{Version: "v7", Default: rules.ActionDeny, Firewall: []rules.Entry{
		{ID: "allow", Action: rules.ActionAllow},
		{ID: "police", Action: rules.ActionRateLimit, RateLimit: &rules.RateLimit{PacketsPerSecond: 5, Burst: 5}},
		{ID: "label", Action: rules.ActionTag, Tag: "x"},
	}}
	if err := e.ApplyRules(ctx, snap); err != nil {
		t.Fatal(err)
	}
	got, err := e.RuleCounters(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if applier.table != "lab_policy" || got.SnapshotVersion != "v7" || !got.Since.Equal(e.RulesetStatus().AppliedAt) || len(got.Rules) != 3 {
		t.Fatalf("counters = %+v read from %q", got, applier.table)
	}
	// Declared in snapshot order: allow, police, police excess, label.
	for i, want := range []struct {
		id      string
		packets uint64
		excess  int64 // -1: none
	}{{"allow", 1, -1}, {"police", 2, 3}, {"label", 4, -1}} {
		rc := got.Rules[i]
		if rc.RuleID != want.id || rc.Packets != want.packets || rc.Bytes != 100*want.packets ||
			(want.excess < 0) != (rc.ExcessDrops == nil) || (rc.ExcessDrops != nil && *rc.ExcessDrops != uint64(want.excess)) {
			t.Fatalf("rule %d = %+v, want %+v", i, rc, want)
		}
	}

	// A failed apply leaves no applied ruleset to report on.
	applier.err = errors.New("nft: busy")
	if err := e.ApplyRules(ctx, snap); err == nil {
		t.Fatal("apply should fail")
	}
	if _, err := e.RuleCounters(ctx); !errors.Is(err, ErrRuleCountersUnavailable) {
		t.Fatalf("after a failed apply: %v", err)
	}
}

func TestRuleCountersNeedEnforcement(t *testing.T) {
	e, err := New(Config{})
	if err != nil {
		t.Fatal(err)
	}
	if err := e.ApplyRules(context.Background(), rules.Snapshot{Version: "v1"}); err != nil {
		t.Fatal(err)
	}
	if _, err := e.RuleCounters(context.Background()); !errors.Is(err, ErrRuleCountersUnavailable) {
		t.Fatalf("without enforcement: %v", err)
	}
	if _, err := (*Engine)(nil).RuleCounters(context.Background()); !errors.Is(err, ErrRuleCountersUnavailable) {
		t.Fatalf("nil engine: %v", err)
	}
}
