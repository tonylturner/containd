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
			Schedule: rules.SchedulePredicate{DaysOfWeek: []string{"Saturday"}}},
		{ID: "plain", Protocols: []rules.Protocol{{Name: "tcp", Port: "443"}}, Action: rules.ActionAllow},
	}}
	applier := &recordingApplier{}
	e, err := New(Config{Enforce: EnforceConfig{Enabled: true, Applier: applier}})
	if err != nil {
		t.Fatal(err)
	}
	if err := e.ApplyRules(context.Background(), snap); err != nil {
		t.Fatal(err)
	}
	want := []enforce.RuleWarning{{RuleID: "maint", Predicate: enforce.PredicateSchedule, Action: rules.ActionAllow,
		Message: "schedules are enforced only on ICS rules inspected through NFQUEUE; ALLOW rule inactive"}}
	if st := e.RulesetStatus(); st.Error != "" || !reflect.DeepEqual(st.Warnings, want) {
		t.Fatalf("status after apply = %+v", st)
	}

	applier.err = errors.New("nft apply failed")
	if err := e.ApplyRules(context.Background(), snap); err == nil {
		t.Fatal("apply error swallowed")
	}
	if st := e.RulesetStatus(); st.Error == "" || st.Warnings != nil {
		t.Fatalf("failed apply status = %+v, want an error and no warnings", st)
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
