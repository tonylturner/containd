// SPDX-License-Identifier: Apache-2.0
package templates

import (
	"slices"
	"strings"
	"testing"
)

func TestModbusTemplateAccessLists(t *testing.T) {
	rules := ModbusReadOnly()
	if !rules[0].ICS.ReadOnly || !slices.Equal(rules[0].ICS.FunctionCode, []uint8{1, 2, 3, 4}) {
		t.Fatalf("read allow=%+v", rules[0])
	}
	if !slices.Equal(rules[1].ICS.FunctionCode, []uint8{5, 6, 15, 16, 21, 22, 23}) ||
		!strings.Contains(rules[1].Description, "FC 21: Write File Record") {
		t.Fatalf("write deny=%+v", rules[1])
	}
}

func TestDNP3TemplateDescribesAllowedOperations(t *testing.T) {
	rules := DNP3SecureOperations()
	if !slices.Equal(rules[0].ICS.FunctionCode, []uint8{0, 1, 20, 21, 23, 24}) {
		t.Fatalf("allow=%+v", rules[0])
	}
	for _, fc := range []string{"FC 0:", "FC 1:", "FC 20:", "FC 21:", "FC 23:", "FC 24:"} {
		if !strings.Contains(rules[0].Description, fc) {
			t.Fatalf("allow description missing %q: %q", fc, rules[0].Description)
		}
	}
	if strings.Contains(strings.ToLower(rules[0].Description), "read-only") {
		t.Fatalf("allow description claims read-only: %q", rules[0].Description)
	}
}
