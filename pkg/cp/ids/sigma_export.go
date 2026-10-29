// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

package ids

import (
	"fmt"
	"strings"

	"github.com/tonylturner/containd/pkg/cp/config"
	"github.com/tonylturner/containd/pkg/dp/ics"
	"gopkg.in/yaml.v3"
)

// ExportSigmaRule is an inverse of containd's Sigma importer, not a mapping to
// a third-party backend schema. Original source is returned byte-for-byte only
// while its matching predicates still agree with the normalized rule.
func ExportSigmaRule(rule config.IDSRule) ([]byte, error) {
	if err := checkExportEnabled(rule, FormatSigma); err != nil {
		return nil, err
	}
	for _, filter := range []struct{ name, value string }{
		{"srcAddr", rule.SrcAddr}, {"dstAddr", rule.DstAddr},
		{"srcPort", rule.SrcPort}, {"dstPort", rule.DstPort},
	} {
		if filter.value != "" {
			return nil, sigmaRefusal(rule, fmt.Sprintf("%s=%q (no importer mapping)", filter.name, filter.value))
		}
	}
	if len(rule.ContentMatches) > 0 {
		return nil, sigmaRefusal(rule, "contentMatches (no Sigma byte-buffer mapping)")
	}
	if len(rule.YARAStrings) > 0 {
		return nil, sigmaRefusal(rule, "yaraStrings (no Sigma byte-buffer mapping)")
	}
	if rule.SourceFormat == FormatSigma && rule.RawSource != "" {
		original, err := ConvertSigmaFile([]byte(rule.RawSource))
		if err != nil || len(original) != 1 {
			return nil, sigmaRefusal(rule, "rawSource (expected one valid Sigma document)")
		}
		if predicate := sigmaPredicateDifference(rule, original[0]); predicate != "" {
			return nil, sigmaRefusal(rule, predicate+" (rawSource disagrees; edit and reimport the source)")
		}
		return []byte(rule.RawSource), nil
	}
	if len(rule.ConversionNotes) > 0 || rule.Labels["evaluable"] == "false" {
		return nil, sigmaRefusal(rule, "conversionNotes/evaluable (unrepresented source predicates)")
	}
	if err := ics.ValidateIDS(rule.ID, rule.Proto); err != nil {
		return nil, sigmaRefusal(rule, fmt.Sprintf("proto=%q (%v)", rule.Proto, err))
	}
	if mapSigmaLevel(rule.Severity) != rule.Severity {
		return nil, sigmaRefusal(rule, fmt.Sprintf("severity=%q", rule.Severity))
	}
	detection := map[string]any{}
	expression, err := sigmaConditionExpression(rule, rule.When, "when", detection)
	if err != nil {
		return nil, err
	}
	detection["condition"] = expression
	sr := sigmaExportRule{ID: rule.ID, Title: firstNonEmpty(rule.Title, rule.ID), Description: rule.Description, Level: rule.Severity,
		Detection: detection, Status: rule.Labels["sigma.status"], References: rule.References}
	if sr.ID == "" {
		return nil, sigmaRefusal(rule, "id (empty native IDs never match)")
	}
	if source := rule.Labels["sigma.logsource"]; source != "" {
		if err := yaml.Unmarshal([]byte(source), &sr.LogSource); err != nil {
			return nil, sigmaRefusal(rule, "sigma.logsource (invalid mapping)")
		}
	}
	if len(sr.References) == 0 && rule.Labels["sigma.references"] != "" {
		sr.References = strings.Split(rule.Labels["sigma.references"], ",")
	}
	for _, tag := range strings.Split(rule.Labels["sigma.tags"], ",") {
		if tag != "" && !sigmaFilterTag(tag) {
			sr.Tags = append(sr.Tags, tag)
		}
	}
	if rule.Proto != "" {
		sr.Tags = append(sr.Tags, "containd.proto."+rule.Proto)
	}
	if rule.Kind != "" {
		sr.Tags = append(sr.Tags, "containd.kind."+rule.Kind)
	}
	data, err := yaml.Marshal(sr)
	if err != nil {
		return nil, err
	}
	// This check also catches YAML scalar coercion and future importer changes.
	decoded, err := ConvertSigmaYAML(data)
	if err != nil {
		return nil, sigmaRefusal(rule, fmt.Sprintf("detection (%v)", err))
	}
	if predicate := sigmaPredicateDifference(rule, decoded); predicate != "" {
		return nil, sigmaRefusal(rule, predicate+" (importer reads the value differently)")
	}
	return data, nil
}

// sigmaExportRule emits metadata supported by the importer without empty fields.
type sigmaExportRule struct {
	Title       string         `yaml:"title"`
	ID          string         `yaml:"id,omitempty"`
	Description string         `yaml:"description,omitempty"`
	Level       string         `yaml:"level,omitempty"`
	Status      string         `yaml:"status,omitempty"`
	Tags        []string       `yaml:"tags,omitempty"`
	LogSource   map[string]any `yaml:"logsource,omitempty"`
	Detection   map[string]any `yaml:"detection"`
	References  []string       `yaml:"references,omitempty"`
}

func sigmaFilterTag(tag string) bool {
	for _, prefix := range []string{"proto.", "kind.", "containd.proto.", "containd.kind."} {
		if strings.HasPrefix(tag, prefix) {
			return true
		}
	}
	return false
}

func sigmaRefusal(rule config.IDSRule, predicate string) error {
	return &RuleExportError{RuleID: rule.ID, Format: FormatSigma, Predicate: predicate}
}

// ExportSigmaRules joins accepted documents without changing predicates. Explicit document
// starts (including directives) must not get a second, empty document before them.
func ExportSigmaRules(rules []config.IDSRule) (ExportResult, error) {
	return exportJoinedRuleSet(rules, func(rule config.IDSRule) (string, error) {
		if len(rules) > 1 && sigmaUTF16Source([]byte(rule.RawSource)) {
			return "", sigmaRefusal(rule, "rawSource encoding (UTF-16 bytes cannot be joined with UTF-8 documents or refusal comments)")
		}
		data, err := ExportSigmaRule(rule)
		text := string(data)
		if len(rules) > 1 {
			text = strings.TrimPrefix(text, "\ufeff")
		} // only a stream may carry a leading encoding BOM
		return text, err
	}, "#", func(body *strings.Builder, text string) {
		if body.Len() > 0 {
			body.WriteByte('\n')
			if !sigmaExplicitDocument(text) {
				body.WriteString("---\n")
			}
		}
		body.WriteString(text)
	})
}
