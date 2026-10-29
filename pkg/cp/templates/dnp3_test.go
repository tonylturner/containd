// SPDX-License-Identifier: Apache-2.0

package templates

import (
	"reflect"
	"testing"

	"github.com/tonylturner/containd/pkg/cp/config"
)

func TestDNP3SecureOperationsSelectors(t *testing.T) {
	rules := DNP3SecureOperations()
	if len(rules) != 3 {
		t.Fatalf("got %d rules, want 3", len(rules))
	}
	want := []config.ICSPredicate{
		{Protocol: "dnp3", FunctionCode: []uint8{0, 1, 20, 21, 23, 24}},
		{Protocol: "dnp3", FunctionCode: []uint8{2}, Groups: []int{50, 80}},
		{Protocol: "dnp3", FunctionCode: []uint8{13, 14, 18, 19}},
	}
	for i, rule := range rules {
		if !reflect.DeepEqual(rule.ICS, want[i]) {
			t.Errorf("rule %s: predicate %+v, want %+v", rule.ID, rule.ICS, want[i])
		}
		action := config.ActionAllow
		if i == 2 {
			action = config.ActionDeny
		}
		if rule.Action != action || !rule.Log || rule.ICS.Mode != "" {
			t.Errorf("rule %s: action/log/inheritance changed", rule.ID)
		}
	}
}
