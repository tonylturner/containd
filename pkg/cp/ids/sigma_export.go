// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

package ids

import (
	"bytes"
	"strings"

	"github.com/tonylturner/containd/pkg/cp/config"
	"gopkg.in/yaml.v3"
)

// ExportSigmaRule converts a containd IDSRule to Sigma YAML bytes.
// If the rule was originally imported from Sigma and has RawSource, it is
// returned as-is for a lossless round-trip.
func ExportSigmaRule(rule config.IDSRule) ([]byte, error) {
	if rule.SourceFormat == "sigma" && rule.RawSource != "" {
		return []byte(rule.RawSource), nil
	}
	sr := buildSigmaRule(rule)
	return yaml.Marshal(sr)
}

// ExportSigmaRules converts multiple IDSRules to a multi-document Sigma YAML.
func ExportSigmaRules(rules []config.IDSRule) ([]byte, error) {
	var buf bytes.Buffer
	for i, rule := range rules {
		if i > 0 {
			buf.WriteString("---\n")
		}
		b, err := ExportSigmaRule(rule)
		if err != nil {
			return nil, err
		}
		buf.Write(b)
	}
	return buf.Bytes(), nil
}

// sigmaExportRule is the output structure for Sigma YAML export.
type sigmaExportRule struct {
	Title       string              `yaml:"title"`
	ID          string              `yaml:"id,omitempty"`
	Description string              `yaml:"description,omitempty"`
	Level       string              `yaml:"level,omitempty"`
	Status      string              `yaml:"status,omitempty"`
	Tags        []string            `yaml:"tags,omitempty"`
	LogSource   map[string]string   `yaml:"logsource,omitempty"`
	Detection   map[string]any      `yaml:"detection,omitempty"`
	References  []string            `yaml:"references,omitempty"`
	Fields      []string            `yaml:"fields,omitempty"`
}

func buildSigmaRule(rule config.IDSRule) sigmaExportRule {
	sr := sigmaExportRule{
		Title:       firstNonEmpty(rule.Title, rule.ID),
		ID:          rule.ID,
		Description: rule.Description,
		Level:       mapSeverityToSigmaLevel(rule.Severity),
		References:  rule.References,
	}

	// Build tags from proto/kind and preserved sigma tags.
	var tags []string
	if rule.Proto != "" {
		tags = append(tags, "containd.proto."+rule.Proto)
	}
	if rule.Kind != "" {
		tags = append(tags, "containd.kind."+rule.Kind)
	}
	if st, ok := rule.Labels["sigma.tags"]; ok {
		for _, t := range strings.Split(st, ",") {
			t = strings.TrimSpace(t)
			if t != "" && !containsString(tags, t) {
				tags = append(tags, t)
			}
		}
	}
	if len(tags) > 0 {
		sr.Tags = tags
	}

	// Restore sigma.status.
	if s, ok := rule.Labels["sigma.status"]; ok {
		sr.Status = s
	}

	// Restore logsource.
	if ls, ok := rule.Labels["sigma.logsource"]; ok {
		m := map[string]string{}
		_ = yaml.Unmarshal([]byte(ls), &m)
		if len(m) > 0 {
			sr.LogSource = m
		}
	}

	// Build detection from IDSCondition.
	det := buildSigmaDetection(rule.When)
	if len(det) > 0 {
		sr.Detection = det
	}

	return sr
}

// buildSigmaDetection converts an IDSCondition tree back to a Sigma detection map.
func buildSigmaDetection(cond config.IDSCondition) map[string]any {
	if isEmptyCondition(cond) {
		return nil
	}

	det := map[string]any{}
	selName := conditionToSelection(cond, det, "selection", 0)
	det["condition"] = selName
	return det
}

// conditionToSelection recursively converts an IDSCondition to Sigma selections.
// Returns the condition expression string.
func conditionToSelection(cond config.IDSCondition, det map[string]any, prefix string, counter int) string {
	// Leaf condition.
	if cond.Field != "" {
		selName := prefix
		if counter > 0 {
			selName = prefix + "_" + strings.ReplaceAll(cond.Field, ".", "_")
		}
		fieldKey := reverseNormalizeField(cond.Field)
		if cond.Op != "" && cond.Op != "equals" {
			fieldKey += "|" + cond.Op
		}
		det[selName] = map[string]any{fieldKey: cond.Value}
		return selName
	}

	// NOT condition.
	if cond.Not != nil {
		inner := conditionToSelection(*cond.Not, det, prefix+"_not", 0)
		return "not " + inner
	}

	// ALL (and) condition.
	if len(cond.All) > 0 {
		var parts []string
		for i, sub := range cond.All {
			name := conditionToSelection(sub, det, prefix, i)
			parts = append(parts, name)
		}
		if len(parts) == 1 {
			return parts[0]
		}
		return "(" + strings.Join(parts, " and ") + ")"
	}

	// ANY (or) condition.
	if len(cond.Any) > 0 {
		var parts []string
		for i, sub := range cond.Any {
			name := conditionToSelection(sub, det, prefix, i)
			parts = append(parts, name)
		}
		if len(parts) == 1 {
			return parts[0]
		}
		return "(" + strings.Join(parts, " or ") + ")"
	}

	return prefix
}

func reverseNormalizeField(f string) string {
	f = strings.TrimPrefix(f, "attr.")
	return f
}

func mapSeverityToSigmaLevel(sev string) string {
	switch strings.ToLower(sev) {
	case "low":
		return "low"
	case "medium":
		return "medium"
	case "high":
		return "high"
	case "critical":
		return "critical"
	default:
		return ""
	}
}

func isEmptyCondition(c config.IDSCondition) bool {
	return c.Field == "" && c.Not == nil && len(c.All) == 0 && len(c.Any) == 0
}

func containsString(ss []string, s string) bool {
	for _, v := range ss {
		if v == s {
			return true
		}
	}
	return false
}
