// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 containd Authors

package engine

import (
	"context"
	"github.com/tonylturner/containd/pkg/dp/rules"
	"sync"
	"testing"
)

func TestRuleEvaluatorReusedUntilSnapshotSwap(t *testing.T) {
	e := newOrientationEngine(t)
	e.LoadRules(rules.Snapshot{Default: rules.ActionAllow})
	first := e.ruleSnap.Evaluator()
	for range 10 {
		if got := e.Evaluate(rules.EvalContext{}); got != rules.ActionAllow {
			t.Fatal(got)
		}
		e.EvaluateVerdictMatch(rules.EvalContext{})
		if e.ruleSnap.Evaluator() != first {
			t.Fatal("evaluator rebuilt for event")
		}
	}
	if err := e.ApplyRules(context.Background(), rules.Snapshot{Default: rules.ActionDeny}); err != nil {
		t.Fatal(err)
	}
	if e.ruleSnap.Evaluator() == first {
		t.Fatal("old evaluator retained after swap")
	}
	if got := e.Evaluate(rules.EvalContext{}); got != rules.ActionDeny {
		t.Fatal(got)
	}
	e.LoadRules(rules.Snapshot{Default: rules.ActionAllow})
	if got := e.Evaluate(rules.EvalContext{}); got != rules.ActionAllow {
		t.Fatal(got)
	}
}

func TestRuleSnapshotConcurrentEvaluation(t *testing.T) {
	var r ruleSnapshots
	var wg sync.WaitGroup
	for range 4 {
		wg.Go(func() {
			for range 1000 {
				if p := r.current.Load(); p != nil && p.evaluator.Evaluate(rules.EvalContext{}) != p.snapshot.Default {
					t.Error("mixed rule generations")
				}
				r.Evaluator().Evaluate(rules.EvalContext{})
			}
		})
	}
	for i := range 1000 {
		action := rules.ActionAllow
		if i%2 == 0 {
			action = rules.ActionDeny
		}
		r.Store(&rules.Snapshot{Default: action})
	}
	wg.Wait()
}
