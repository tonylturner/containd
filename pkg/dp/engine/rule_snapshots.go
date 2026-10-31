// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 containd Authors

package engine

import (
	"sync/atomic"
	"time"

	"github.com/tonylturner/containd/pkg/dp/rules"
)

// ruleSnapshots publishes an immutable snapshot and its compiled evaluator
// together. Readers never compile rules or see mismatched generations.
type ruleSnapshots struct{ current atomic.Pointer[compiledRules] }
type compiledRules struct {
	snapshot  *rules.Snapshot
	evaluator *rules.Evaluator
	shadow    *shadowState
}

var emptyRulesEvaluator = rules.NewEvaluator(nil)

func (r *ruleSnapshots) Store(snap *rules.Snapshot) {
	r.current.Store(&compiledRules{snapshot: snap, evaluator: rules.NewEvaluator(snap)})
}

func (r *ruleSnapshots) Load() *rules.Snapshot {
	if p := r.current.Load(); p != nil {
		return p.snapshot
	}
	return nil
}

func (r *ruleSnapshots) Evaluator() *rules.Evaluator {
	if p := r.current.Load(); p != nil {
		return p.evaluator
	}
	return emptyRulesEvaluator
}

func (r *ruleSnapshots) Install(snap *rules.Snapshot, since time.Time) {
	r.current.Store(&compiledRules{snapshot: snap, evaluator: rules.NewEvaluator(snap), shadow: newShadowState(snap, since)})
}
