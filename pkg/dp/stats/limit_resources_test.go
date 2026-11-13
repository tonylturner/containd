// SPDX-License-Identifier: Apache-2.0

package stats

import (
	"testing"

	"github.com/tonylturner/containd/pkg/dp/limits"
)

func TestLimitResourceInjection(t *testing.T) {
	o := New()
	if o.resources.Budget == nil || o.resources.Ledger == nil || o.stateLimits != limits.Default() {
		t.Fatal("standalone owner lacks finite defaults")
	}
	budget, ledger := limits.NewBudget(7), limits.NewLedger(nil)
	l := limits.Default()
	l.MaxTopTalkers = 1
	o.SetLimits(l, budget, ledger)
	if o.resources.Budget != budget || o.resources.Ledger != ledger || o.stateLimits != l {
		t.Fatal("lost injected generation")
	}
	o.SetLimits(l, nil, nil)
	if o.resources.Budget == budget || o.resources.Ledger == ledger || o.resources.Budget.Status().Limit != limits.DefaultMaxInspectionBytes {
		t.Fatal("nil injection is not private/default")
	}
}
