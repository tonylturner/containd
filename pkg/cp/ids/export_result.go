// SPDX-License-Identifier: Apache-2.0
package ids

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/tonylturner/containd/pkg/cp/config"
)

// ExportRefusal identifies a rule that could not be represented without loss.
type ExportRefusal struct {
	RuleID string `json:"rule_id"`
	Reason string `json:"reason"`
}

// ExportResult includes downloadable text and every refused rule.
// Text includes one JSON comment per refusal, using the target comment syntax.
type ExportResult struct {
	Text     []byte
	Refusals []ExportRefusal
}

// RuleExportError names the first predicate that cannot be preserved.
type RuleExportError struct {
	RuleID    string
	Predicate string
	Format    string
	protocol  bool
}

func (e *RuleExportError) Error() string {
	return fmt.Sprintf("rule %q: %s cannot preserve %s", e.RuleID, e.Format, e.Predicate)
}

// Is retains the protocol refusal category for callers using errors.Is.
func (e *RuleExportError) Is(target error) bool {
	return e.protocol && target == ErrUnexportableProto
}

func exportRulesFile(rules []config.IDSRule, single func(config.IDSRule) (string, error)) (ExportResult, error) {
	return exportRuleSet(rules, single, "#", "")
}

func exportRuleSet(rules []config.IDSRule, single func(config.IDSRule) (string, error), comment, separator string) (ExportResult, error) {
	return exportJoinedRuleSet(rules, single, comment, func(body *strings.Builder, text string) {
		if body.Len() > 0 {
			body.WriteString(separator)
		}
		body.WriteString(text)
		body.WriteByte('\n')
	})
}

func exportJoinedRuleSet(rules []config.IDSRule, single func(config.IDSRule) (string, error), comment string, join func(*strings.Builder, string)) (ExportResult, error) {
	var result ExportResult
	var body strings.Builder
	for _, rule := range rules {
		text, err := single(rule)
		if err != nil {
			var refusal *RuleExportError
			if !errors.As(err, &refusal) {
				return ExportResult{}, err
			}
			result.Refusals = append(result.Refusals, ExportRefusal{RuleID: refusal.RuleID, Reason: refusal.Error()})
			continue
		}
		join(&body, text)
	}
	var out bytes.Buffer
	if len(result.Refusals) > 0 {
		fmt.Fprintf(&out, "%s containd: %d rule(s) refused; not included below\n", comment, len(result.Refusals))
		for _, refusal := range result.Refusals {
			// JSON escaping keeps untrusted IDs and predicates on one comment
			// line, including embedded newlines and Unicode line separators.
			data, err := json.Marshal(refusal)
			if err != nil {
				return ExportResult{}, err
			}
			fmt.Fprintf(&out, "%s refused: %s\n", comment, data)
		}
	}
	out.WriteString(body.String())
	result.Text = out.Bytes()
	return result, nil
}
