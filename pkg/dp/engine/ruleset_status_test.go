// SPDX-License-Identifier: Apache-2.0

package engine

import (
	"context"
	"errors"
	"reflect"
	"testing"

	"github.com/tonylturner/containd/pkg/dp/enforce"
	"github.com/tonylturner/containd/pkg/dp/rules"
)

func TestRulesetStatusCarriesAppliedWarnings(t *testing.T) {
	snap := rules.Snapshot{Default: rules.ActionDeny, Firewall: []rules.Entry{
		{ID: "maint", Protocols: []rules.Protocol{{Name: "tcp", Port: "22"}}, Action: rules.ActionAllow,
			Identities: []string{"operator"}},
		{ID: "plain", Protocols: []rules.Protocol{{Name: "tcp", Port: "443"}}, Action: rules.ActionAllow},
	}}
	applier := &recordingApplier{}
	e, err := New(Config{Enforce: EnforceConfig{ClearMark: noPolicyMarks, Enabled: true, Applier: applier}})
	if err != nil {
		t.Fatal(err)
	}
	if err := e.ApplyRules(context.Background(), snap); err != nil {
		t.Fatal(err)
	}
	want := []enforce.RuleWarning{{RuleID: "maint", Predicate: enforce.PredicateIdentity, Action: rules.ActionAllow,
		Message: "no bound address can match identities operator; the rule matches nothing until one is bound"}}
	if st := e.RulesetStatus(); st.Error != "" || !reflect.DeepEqual(st.Warnings, want) {
		t.Fatalf("status after apply = %+v", st)
	}

	applier.err = errors.New("nft apply failed")
	if err := e.ApplyRules(context.Background(), rules.Snapshot{Default: rules.ActionDeny}); err == nil {
		t.Fatal("apply error swallowed")
	}
	if st := e.RulesetStatus(); st.Error == "" || !reflect.DeepEqual(st.Warnings, want) {
		t.Fatalf("failed apply status = %+v, want the error and the installed ruleset's warnings", st)
	}

	disabled, err := New(Config{})
	if err != nil {
		t.Fatal(err)
	}
	if err := disabled.ApplyRules(context.Background(), snap); err != nil {
		t.Fatal(err)
	}
	if st := disabled.RulesetStatus(); st.Ruleset != "" || st.Warnings != nil {
		t.Fatalf("status without enforcement = %+v, want no ruleset and no warnings", st)
	}
}

// A failed apply leaves the installed ruleset in place, and the status
// keeps describing it, with the failed snapshot and its error added until
// the next successful apply.
func TestRulesetStatusKeepsInstalledRevisionOnFailedApply(t *testing.T) {
	applier := &recordingApplier{}
	e, err := New(Config{Enforce: EnforceConfig{ClearMark: noPolicyMarks, Enabled: true, Applier: applier}})
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	applier.err = errors.New("nft apply failed")
	if err := e.ApplyRules(ctx, rules.Snapshot{Version: "v0", Default: rules.ActionDeny}); err == nil {
		t.Fatal("apply error swallowed")
	}
	if st := e.RulesetStatus(); st.SnapshotVersion != "" || !st.AppliedAt.IsZero() || st.Ruleset != "" || st.FailedSnapshotVersion != "v0" || st.FailedAt == nil || st.Error == "" {
		t.Fatalf("status of a failed first apply = %+v, want nothing installed", st)
	}
	applier.err = nil
	if err := e.ApplyRules(ctx, rules.Snapshot{Version: "v1", Default: rules.ActionDeny}); err != nil {
		t.Fatal(err)
	}
	installed := e.RulesetStatus()
	if installed.SnapshotVersion != "v1" || installed.Error != "" || installed.FailedSnapshotVersion != "" || installed.FailedAt != nil || installed.Ruleset == "" {
		t.Fatalf("status after apply = %+v", installed)
	}
	applier.err = errors.New("nft apply failed")
	if err := e.ApplyRules(ctx, rules.Snapshot{Version: "v2", Default: rules.ActionAllow}); err == nil {
		t.Fatal("apply error swallowed")
	}
	st := e.RulesetStatus()
	if st.SnapshotVersion != "v1" || !st.AppliedAt.Equal(installed.AppliedAt) || st.Ruleset != installed.Ruleset {
		t.Fatalf("status after failed apply = %+v, want installed v1 %+v", st, installed)
	}
	if st.FailedSnapshotVersion != "v2" || st.FailedAt == nil || st.Error != "nft apply failed" {
		t.Fatalf("failed apply not recorded: %+v", st)
	}
	applier.err = nil
	if err := e.ApplyRules(ctx, rules.Snapshot{Version: "v3", Default: rules.ActionDeny}); err != nil {
		t.Fatal(err)
	}
	if st := e.RulesetStatus(); st.SnapshotVersion != "v3" || st.Error != "" || st.FailedSnapshotVersion != "" || st.FailedAt != nil {
		t.Fatalf("status after the next apply = %+v", st)
	}
}

// Turning enforcement off deletes the installed tables, so the status stops
// describing a ruleset; it keeps the loaded snapshot, as an engine that
// never enforced reports it.
func TestRulesetStatusAfterReleaseReportsNothingInstalled(t *testing.T) {
	applier := &recordingApplier{}
	e, err := New(Config{Enforce: EnforceConfig{ClearMark: noPolicyMarks, Enabled: true, Applier: applier}})
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	snap := rules.Snapshot{Version: "v1", Default: rules.ActionDeny, Firewall: []rules.Entry{
		{ID: "maint", Protocols: []rules.Protocol{{Name: "tcp", Port: "22"}}, Action: rules.ActionAllow, Identities: []string{"operator"}}}}
	if err := e.ApplyRules(ctx, snap); err != nil {
		t.Fatal(err)
	}
	applier.err = errors.New("nft apply failed")
	if err := e.ApplyRules(ctx, rules.Snapshot{Version: "v2"}); err == nil {
		t.Fatal("apply error swallowed")
	}
	installed := e.RulesetStatus()
	if installed.Ruleset == "" || installed.Error == "" || installed.Warnings == nil {
		t.Fatalf("status before release = %+v", installed)
	}
	applier.err = nil
	disabled, err := New(Config{})
	if err != nil {
		t.Fatal(err)
	}
	if err := e.Reconfigure(disabled); err != nil {
		t.Fatal(err)
	}
	st := e.RulesetStatus()
	if st.Ruleset != "" || st.Warnings != nil || st.Error != "" || st.FailedSnapshotVersion != "" || st.FailedAt != nil {
		t.Fatalf("status after release = %+v, want no installed ruleset", st)
	}
	if st.SnapshotVersion != "v1" || !st.AppliedAt.Equal(installed.AppliedAt) {
		t.Fatalf("status after release = %+v, want the loaded snapshot v1 applied at %v", st, installed.AppliedAt)
	}
}
