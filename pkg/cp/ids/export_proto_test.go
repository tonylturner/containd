// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

package ids

import (
	"errors"
	"strings"
	"testing"

	"github.com/tonylturner/containd/pkg/cp/config"
)

// IEC104 rules are refused instead of being rendered as generic IP.
func TestExportRefusesIEC104Rules(t *testing.T) {
	rules := []config.IDSRule{
		{ID: "1", Title: "TCP rule", Proto: "tcp"},
		{ID: "2", Title: "IEC104 command", Proto: "iec104"},
		{ID: "3", Title: "IEC104 STOPDT", Proto: " IEC104 "},
	}
	for _, tc := range []struct {
		name   string
		single func(config.IDSRule) (string, error)
		multi  func([]config.IDSRule) (ExportResult, error)
	}{
		{"suricata", ExportSuricataRule, ExportSuricataRules},
		{"snort", ExportSnortRule, ExportSnortRules},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := tc.single(rules[1]); !errors.Is(err, ErrUnexportableProto) {
				t.Fatalf("single IEC104 export err = %v, want ErrUnexportableProto", err)
			}
			out, err := tc.multi(rules)
			if err != nil {
				t.Fatalf("export: %v", err)
			}
			var lines []string
			for _, line := range strings.Split(strings.TrimSpace(string(out.Text)), "\n") {
				if !strings.HasPrefix(line, "#") {
					lines = append(lines, line)
				}
			}
			if len(lines) != 1 || !strings.Contains(lines[0], "TCP rule") {
				t.Fatalf("export = %q, want only the TCP rule", out)
			}
			if len(out.Refusals) != 2 {
				t.Fatalf("refusals = %+v", out.Refusals)
			}
		})
	}
}
