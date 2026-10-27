// SPDX-License-Identifier: Apache-2.0

package engine

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/tonylturner/containd/pkg/dp/enforce"
)

// RuleCounters is the kernel accounting of the applied ruleset, per
// firewall rule in snapshot order. Each apply replaces the policy table,
// so the counters start at zero at Since.
type RuleCounters struct {
	SnapshotVersion string              `json:"snapshotVersion"`
	Since           time.Time           `json:"since"`
	Rules           []enforce.RuleCount `json:"rules"`
}

// ErrRuleCountersUnavailable reports that no applied ruleset can be read:
// enforcement is off or nothing is applied yet. A failed apply leaves the
// installed ruleset, and its counters, in place.
var ErrRuleCountersUnavailable = errors.New("rule counters unavailable")

// RuleCounters reads the counters of the applied ruleset. It holds the
// lifecycle lock, so the snapshot, its apply time and the table read
// belong to the same apply.
func (e *Engine) RuleCounters(ctx context.Context) (RuleCounters, error) {
	if e == nil {
		return RuleCounters{}, fmt.Errorf("%w: no engine", ErrRuleCountersUnavailable)
	}
	e.lifecycleMu.Lock()
	defer e.lifecycleMu.Unlock()
	table, applier := e.gate.installedPolicy()
	reader, ok := applier.(enforce.CounterReader)
	if table == "" || !ok {
		return RuleCounters{}, fmt.Errorf("%w: nftables enforcement is not active", ErrRuleCountersUnavailable)
	}
	st := e.rulesetStatus.Load()
	snap := e.ruleSnap.Load()
	if st == nil || st.AppliedAt.IsZero() || snap == nil {
		return RuleCounters{}, fmt.Errorf("%w: no ruleset is applied", ErrRuleCountersUnavailable)
	}
	counters, err := reader.ReadCounters(ctx, table)
	if err != nil {
		return RuleCounters{}, err
	}
	counts, err := enforce.RuleCounts(snap, counters)
	if err != nil {
		return RuleCounters{}, err
	}
	return RuleCounters{SnapshotVersion: st.SnapshotVersion, Since: st.AppliedAt, Rules: counts}, nil
}

// installedPolicy returns the policy table of the installed ruleset and
// its applier; "" when none is installed.
func (g *envelopeGate) installedPolicy() (string, enforce.Applier) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.comp == nil {
		return "", nil
	}
	return g.comp.PolicyTable(), g.applier
}
