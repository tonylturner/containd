// SPDX-License-Identifier: Apache-2.0
package metrics

import (
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/tonylturner/containd/pkg/dp/limits"
)

func TestStateLimitsCollector(t *testing.T) {
	defer SetStateLimitsReader(nil)
	registry := prometheus.NewPedanticRegistry()
	registry.MustRegister(stateLimitsCollector{})
	total := uint64(3)
	SetStateLimitsReader(func() limits.Snapshot {
		return limits.Snapshot{Tables: []limits.TableStatus{
			{Table: limits.TableFlows, Limit: 1024, Entries: 2, ChargedBytes: 512, HighWater: 4, Hits: []limits.Hit{
				{Reason: limits.ReasonRefused, Mode: limits.ModeEnforce, Total: total},
				{Reason: "untrusted", Mode: "identity", Total: 9},
			}},
			{Table: "untrusted", Entries: 999},
		}, Budget: limits.BudgetStatus{ByCategory: map[string]int64{"stream": 512, "identity": 999}}}
	})
	for _, want := range []uint64{3, 7} {
		total = want
		families, err := registry.Gather()
		if err != nil {
			t.Fatal(err)
		}
		if len(families) != 6 {
			t.Fatalf("families=%d", len(families))
		}
		seen := false
		for _, family := range families {
			for _, metric := range family.Metric {
				for _, label := range metric.Label {
					if label.GetValue() == "untrusted" || label.GetValue() == "identity" {
						t.Fatal(label)
					}
				}
				if family.GetName() == "containd_dp_state_limit_hits_total" && metric.Label[0].GetValue() == "enforce" && metric.Label[1].GetValue() == "refused" {
					if metric.Counter.GetValue() != float64(want) {
						t.Fatal(metric)
					}
					seen = true
				}
			}
		}
		if !seen {
			t.Fatal("missing refusal counter")
		}
	}
	SetStateLimitsReader(nil)
	families, err := registry.Gather()
	if err != nil || len(families) != 0 {
		t.Fatalf("disabled: %v %v", families, err)
	}
}
