// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 containd Authors

package engine

import (
	"github.com/tonylturner/containd/pkg/dp/rules"
	"sync/atomic"
)

// ruleSnapshots publishes an immutable snapshot, its compiled evaluator and
// its entries' address scopes together. Readers never compile rules or see
// mismatched generations.
type ruleSnapshots struct{ current atomic.Pointer[compiledRules] }
type compiledRules struct {
	snapshot  *rules.Snapshot
	evaluator *rules.Evaluator
	scopes    entryScopes
}

var emptyRulesEvaluator = rules.NewEvaluator(nil)

func (r *ruleSnapshots) Store(snap *rules.Snapshot) {
	r.current.Store(&compiledRules{snapshot: snap, evaluator: rules.NewEvaluator(snap), scopes: compileEntryScopes(snap)})
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

// LoadScoped returns the snapshot with the address scopes of its firewall
// entries, by index.
func (r *ruleSnapshots) LoadScoped() (*rules.Snapshot, entryScopes) {
	if p := r.current.Load(); p != nil {
		return p.snapshot, p.scopes
	}
	return nil, nil
}
