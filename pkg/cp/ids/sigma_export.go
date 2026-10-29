// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

package ids

import (
	"fmt"

	"github.com/tonylturner/containd/pkg/cp/config"
)

// ExportSigmaRule preserves original Sigma detection source. Native decoder
// fields have no established Sigma backend field mapping: stripping "attr."
// or turning quick filters into tags cannot preserve their matching semantics.
func ExportSigmaRule(rule config.IDSRule) ([]byte, error) {
	if err := checkExportEnabled(rule, FormatSigma); err != nil {
		return nil, err
	}
	for _, filter := range []struct{ name, value string }{
		{"proto", rule.Proto}, {"kind", rule.Kind},
		{"srcAddr", rule.SrcAddr}, {"dstAddr", rule.DstAddr},
		{"srcPort", rule.SrcPort}, {"dstPort", rule.DstPort},
	} {
		if filter.value != "" {
			return nil, &RuleExportError{RuleID: rule.ID, Format: FormatSigma,
				Predicate: fmt.Sprintf("%s=%q (no exact Sigma field mapping)", filter.name, filter.value)}
		}
	}
	if len(rule.ContentMatches) > 0 || len(rule.YARAStrings) > 0 {
		return nil, &RuleExportError{RuleID: rule.ID, Format: FormatSigma,
			Predicate: "contentMatches or yaraStrings (no exact Sigma byte-buffer mapping)"}
	}
	if rule.SourceFormat == FormatSigma && rule.RawSource != "" {
		return []byte(rule.RawSource), nil
	}
	predicate := unsupportedCondition(rule.When, "when")
	if predicate == "" {
		predicate = "detection (no original Sigma source or exact native field mapping)"
	}
	return nil, &RuleExportError{RuleID: rule.ID, Format: FormatSigma, Predicate: predicate}
}

// ExportSigmaRules joins accepted documents, reporting every refused rule.
func ExportSigmaRules(rules []config.IDSRule) (ExportResult, error) {
	return exportRuleSet(rules, func(rule config.IDSRule) (string, error) {
		data, err := ExportSigmaRule(rule)
		return string(data), err
	}, "#", "---\n")
}
