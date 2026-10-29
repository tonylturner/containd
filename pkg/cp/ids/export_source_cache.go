// SPDX-License-Identifier: Apache-2.0
package ids

import (
	"errors"
	"fmt"
	"strings"

	"github.com/tonylturner/containd/pkg/cp/config"
)

// exportWithSourceCache shares the same cache policy across all formats. Only
// one successfully imported rule with equivalent predicates validates a cache.
// Native export still receives conversion notes and evaluability guards: a
// stale or corrupt cache is not permission to discard unrepresented predicates.
func exportWithSourceCache(rule config.IDSRule, format string, native func(config.IDSRule) (string, error)) (string, error) {
	if err := checkExportEnabled(rule, format); err != nil {
		return "", err
	}
	var difference string
	if rule.SourceFormat == format && rule.RawSource != "" {
		original, err := ImportRules([]byte(rule.RawSource), format)
		if err == nil && len(original) == 1 {
			difference = rulePredicateDifference(rule, original[0])
			if difference == "" {
				return rule.RawSource, nil
			}
		}
	}
	text, err := native(rule)
	var refusal *RuleExportError
	if difference != "" && errors.As(err, &refusal) && !strings.Contains(refusal.Predicate, difference) {
		// Keep the edited predicate visible even when loss recorded by the importer
		// is the reason that native regeneration cannot safely proceed.
		copy := *refusal
		copy.Predicate = fmt.Sprintf("%s (native export: %s)", difference, refusal.Predicate)
		return "", &copy
	}
	return text, err
}
