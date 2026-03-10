// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

package ids

import (
	"bytes"
	"fmt"
	"strings"

	"github.com/tonylturner/containd/pkg/cp/config"
)

// ExportYARARule converts a containd IDSRule to a YARA rule string.
// If the rule was originally imported from YARA and has RawSource, it is
// returned as-is for a lossless round-trip.
func ExportYARARule(rule config.IDSRule) (string, error) {
	if rule.SourceFormat == "yara" && rule.RawSource != "" {
		return rule.RawSource, nil
	}
	return buildYARARule(rule), nil
}

// ExportYARARules converts multiple IDSRules to YARA .yar format.
func ExportYARARules(rules []config.IDSRule) ([]byte, error) {
	var buf bytes.Buffer
	for i, rule := range rules {
		if i > 0 {
			buf.WriteString("\n")
		}
		s, err := ExportYARARule(rule)
		if err != nil {
			return nil, err
		}
		buf.WriteString(s)
		buf.WriteString("\n")
	}
	return buf.Bytes(), nil
}

func buildYARARule(rule config.IDSRule) string {
	var sb strings.Builder

	// Rule name: sanitize to valid YARA identifier.
	name := yaraIdentifier(firstNonEmpty(rule.Title, rule.ID))

	// Tags from labels.
	var tags []string
	if t, ok := rule.Labels["yara.tags"]; ok {
		tags = strings.Split(t, ",")
	}

	sb.WriteString("rule ")
	sb.WriteString(name)
	if len(tags) > 0 {
		sb.WriteString(" : ")
		sb.WriteString(strings.Join(tags, " "))
	}
	sb.WriteString(" {\n")

	// Meta section.
	sb.WriteString("    meta:\n")
	if rule.Description != "" {
		sb.WriteString(fmt.Sprintf("        description = \"%s\"\n", escapeYARAString(rule.Description)))
	}
	if author, ok := rule.Labels["author"]; ok {
		sb.WriteString(fmt.Sprintf("        author = \"%s\"\n", escapeYARAString(author)))
	}
	if rule.Severity != "" {
		sb.WriteString(fmt.Sprintf("        severity = \"%s\"\n", rule.Severity))
	}
	for _, ref := range rule.References {
		sb.WriteString(fmt.Sprintf("        reference = \"%s\"\n", escapeYARAString(ref)))
	}
	// Write remaining yara.meta.* labels.
	if rule.Labels != nil {
		for k, v := range rule.Labels {
			if strings.HasPrefix(k, "yara.meta.") {
				metaKey := strings.TrimPrefix(k, "yara.meta.")
				sb.WriteString(fmt.Sprintf("        %s = \"%s\"\n", metaKey, escapeYARAString(v)))
			}
		}
	}

	// Strings section.
	if len(rule.YARAStrings) > 0 {
		sb.WriteString("    strings:\n")
		for _, ys := range rule.YARAStrings {
			sb.WriteString(fmt.Sprintf("        %s = %s\n", ys.Name, formatYARAStringValue(ys)))
		}
	}

	// Condition section.
	sb.WriteString("    condition:\n")
	cond := "any of them"
	if c, ok := rule.Labels["yara.condition"]; ok && c != "" {
		cond = c
	}
	sb.WriteString(fmt.Sprintf("        %s\n", cond))

	sb.WriteString("}")
	return sb.String()
}

func formatYARAStringValue(ys config.YARAString) string {
	var sb strings.Builder
	switch ys.Type {
	case "hex":
		sb.WriteString("{ ")
		sb.WriteString(ys.Pattern)
		sb.WriteString(" }")
	case "regex":
		sb.WriteString("/")
		sb.WriteString(ys.Pattern)
		sb.WriteString("/")
	default: // text
		sb.WriteString("\"")
		sb.WriteString(escapeYARAString(ys.Pattern))
		sb.WriteString("\"")
	}

	if ys.Nocase {
		sb.WriteString(" nocase")
	}
	if ys.Wide {
		sb.WriteString(" wide")
	}
	if ys.ASCII {
		sb.WriteString(" ascii")
	}
	return sb.String()
}

// yaraIdentifier converts a string to a valid YARA rule identifier.
func yaraIdentifier(s string) string {
	s = strings.Map(func(r rune) rune {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '_' {
			return r
		}
		return '_'
	}, s)
	// Must start with a letter or underscore.
	if len(s) > 0 && s[0] >= '0' && s[0] <= '9' {
		s = "_" + s
	}
	if s == "" {
		s = "unnamed_rule"
	}
	// Collapse multiple underscores.
	for strings.Contains(s, "__") {
		s = strings.ReplaceAll(s, "__", "_")
	}
	s = strings.Trim(s, "_")
	return s
}

func escapeYARAString(s string) string {
	s = strings.ReplaceAll(s, `\`, `\\`)
	s = strings.ReplaceAll(s, `"`, `\"`)
	return s
}
