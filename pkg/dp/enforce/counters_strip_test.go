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
	zones, err := newZoneIndex(zoneIfaces)
	if err != nil {
		return nil, err
	}
	lines, err := compileEntry(e, zoneLowering{idx: zones}, queueID, nflogGroup)
	texts := make([]string, 0, len(lines))
	for _, l := range lines {
		texts = append(texts, withoutRuleCounters(l.text))
	}
	return texts, err
}

// guardedWithoutCounters is compileEntryWithoutCounters with p's predicates.
func guardedWithoutCounters(p *predicates, e rules.Entry) ([]string, error) {
	lines, err := compileEntry(e, p.lowering(targetForward), p.queueID, 0)
	if err != nil {
		return nil, err
	}
	guarded, err := p.guard(e, lines)
	for i := range guarded {
		guarded[i] = withoutRuleCounters(guarded[i])
	}
	return guarded, err
}
