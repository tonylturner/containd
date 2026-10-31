// SPDX-License-Identifier: Apache-2.0

package enforce

import (
	"regexp"

	"github.com/tonylturner/containd/pkg/dp/rules"
)

// Tests of rule matching and verdicts compare lines without the rule
// counter statement every line carries; counters_test.go covers counters.
var ruleCounterStmt = regexp.MustCompile(`counter name "rule_[0-9a-f]{16}" `)

func withoutRuleCounters(s string) string {
	return ruleCounterStmt.ReplaceAllString(s, "")
}

func compileWithoutCounters(c *Compiler, snap *rules.Snapshot) (string, error) {
	text, err := c.CompileFirewall(snap)
	return withoutRuleCounters(text), err
}

func headerLinesText(e rules.Entry, tail string) ([]string, error) {
	lines, err := headerLines(e, zoneLowering{}, tail)
	var out []string
	for _, line := range lines {
		out = append(out, line.text)
	}
	return out, err
}
