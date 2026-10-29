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
	if !slices.Equal(rules[0].ICS.FunctionCode, []uint8{1, 2, 20}) ||
		!strings.Contains(rules[0].Description, "FC 2: Write, FC 20: Enable Unsolicited") ||
		!strings.Contains(rules[0].Description, "not read-only") {
		t.Fatalf("allow=%+v", rules[0])
	}
}
