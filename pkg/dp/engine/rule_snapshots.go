// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 containd Authors

package engine

import (
	"sync"
	"sync/atomic"
	"time"

	"github.com/tonylturner/containd/pkg/dp/rules"
)

// ruleSnapshots publishes an immutable snapshot and its compiled evaluator
// together. Readers never compile rules or see mismatched generations.
type ruleSnapshots struct {
	current   atomic.Pointer[compiledRules]
	publishMu sync.Mutex
	nextEpoch rulesEpoch
}
type compiledRules struct {
	epoch     rulesEpoch
	snapshot  *rules.Snapshot
	evaluator *rules.Evaluator
	shadow    *shadowState
}

var emptyRulesEvaluator = rules.NewEvaluator(nil)

func (r *ruleSnapshots) Store(snap *rules.Snapshot) {
	r.publish(snap, nil, false)
}

// Update publishes resolver inputs without resetting install counters.
func (r *ruleSnapshots) Update(snap *rules.Snapshot) {
	r.publish(snap, nil, true)
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
	r.publish(snap, newShadowState(snap, since), false)
}

// Every publication allocates under the same lock, independently of the public
// snapshot version. Compilation and Store cannot reorder concurrent epochs.
func (r *ruleSnapshots) publish(snap *rules.Snapshot, shadow *shadowState, preserveCounters bool) {
	r.publishMu.Lock()
	defer r.publishMu.Unlock()
	if preserveCounters {
		if old := r.current.Load(); old != nil {
			shadow = old.shadow
		}
	}
	r.nextEpoch++
	r.current.Store(&compiledRules{epoch: r.nextEpoch, snapshot: snap, evaluator: rules.NewEvaluator(snap), shadow: shadow})
}
