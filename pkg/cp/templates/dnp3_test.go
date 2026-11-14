// SPDX-License-Identifier: Apache-2.0

package templates

import (
	"reflect"
	"testing"

	"github.com/tonylturner/containd/pkg/cp/config"
)

func TestDS34ConsumersDNP3SecureOperationsSelectors(t *testing.T) {
	rules := DNP3SecureOperations()
	if len(rules) != 6 {
		t.Fatalf("got %d rules, want 6", len(rules))
	}
	want := []config.ICSPredicate{
		{Protocol: "dnp3", FunctionCode: []uint8{1, 20, 21, 23, 24}},
		{Protocol: "dnp3", FunctionCode: []uint8{2}, Groups: []int{50, 80}},
		{Protocol: "dnp3", MessageClass: "session", Direction: "request"},
		{Protocol: "dnp3", MessageClass: "session", Direction: "response"},
		{Protocol: "dnp3", MessageClass: "autonomous", Direction: "response"},
		{Protocol: "dnp3", FunctionCode: []uint8{13, 14, 18, 19}},
	}
	for i, rule := range rules {
		if !reflect.DeepEqual(rule.ICS, want[i]) {
			t.Errorf("rule %s: predicate %+v, want %+v", rule.ID, rule.ICS, want[i])
		}
		action := config.ActionAllow
		if i == 5 {
			action = config.ActionDeny
		}
		if rule.Action != action || !rule.Log || rule.ICS.Mode != "" {
			t.Errorf("rule %s: action/log/inheritance changed", rule.ID)
		}
	}
}

func TestDS34ConsumersDNP3UnsolicitedAllowance(t *testing.T) {
	allowances := 0
	for _, rule := range DNP3SecureOperations() {
		if rule.ICS.MessageClass != "autonomous" || rule.Action != config.ActionAllow {
			continue
		}
		allowances++
		if rule.ID != "tpl-dnp3-unsolicited" {
			t.Errorf("unexpected autonomous allowance %q", rule.ID)
		}
		want := config.ICSPredicate{
			Protocol:     "dnp3",
			MessageClass: "autonomous",
			Direction:    "response",
		}
		if !reflect.DeepEqual(rule.ICS, want) {
			t.Errorf("unsolicited predicate = %+v, want %+v", rule.ICS, want)
		}
		if !reflect.DeepEqual(rule.Protocols, []config.Protocol{{Name: "tcp", Port: "20000"}}) || !rule.Log {
			t.Errorf("unsolicited rule must log and use only TCP port 20000: %+v", rule)
		}
		const description = "Allow DNP3 outstation unsolicited responses for master-enabled reporting; this rule does not require a preceding Enable Unsolicited request."
		if rule.Description != description {
			t.Errorf("unsolicited description = %q, want %q", rule.Description, description)
		}
	}
	if allowances != 1 {
		t.Fatalf("got %d autonomous allowances, want exactly one", allowances)
	}
}
