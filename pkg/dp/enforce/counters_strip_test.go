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

func compileEntryWithoutCounters(e rules.Entry, zoneIfaces map[string][]string, queueID, nflogGroup int) ([]string, error) {
	lines, err := compileEntry(e, zoneIfaces, queueID, nflogGroup)
	for i := range lines {
		lines[i] = withoutRuleCounters(lines[i])
	}
	return lines, err
}
