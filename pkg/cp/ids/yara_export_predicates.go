// SPDX-License-Identifier: Apache-2.0
package ids

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/tonylturner/containd/pkg/cp/config"
)

var (
	yaraExportIdentifier = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)
	yaraExportHex        = regexp.MustCompile(`^(?:[0-9A-Fa-f]{2}[ \t]+)*[0-9A-Fa-f]{2}$`)
)

func checkYARAExportPredicates(rule config.IDSRule) error {
	if err := checkExportEnabled(rule, FormatYARA); err != nil {
		return err
	}
	refuse := func(predicate string) error {
		return &RuleExportError{RuleID: rule.ID, Format: FormatYARA, Predicate: predicate}
	}
	// Even original YARA source cannot carry added decoder/event constraints.
	for _, filter := range []struct{ name, value string }{
		{"proto", rule.Proto}, {"kind", rule.Kind},
		{"srcAddr", rule.SrcAddr}, {"dstAddr", rule.DstAddr},
		{"srcPort", rule.SrcPort}, {"dstPort", rule.DstPort},
	} {
		if filter.value != "" {
			return refuse(fmt.Sprintf("%s=%q", filter.name, filter.value))
		}
	}
	if predicate := unsupportedCondition(rule.When, "when"); predicate != "" {
		return refuse(predicate)
	}
	if len(rule.ContentMatches) > 0 {
		return refuse("contentMatches (network inspection buffers are not YARA byte buffers)")
	}
	if rule.SourceFormat == FormatYARA && rule.RawSource != "" {
		return nil
	}
	if rule.SourceFormat != "" && rule.SourceFormat != FormatNative {
		return refuse("sourceFormat (original YARA source required for imported rules)")
	}
	if len(rule.ConversionNotes) > 0 {
		return refuse("conversionNotes (unrepresented source predicates)")
	}
	if rule.Action != "" || rule.Labels["sigma.logsource"] != "" {
		return refuse("action or Sigma logsource")
	}
	if len(rule.YARAStrings) == 0 {
		return refuse("yaraStrings (pure content required)")
	}
	if !yaraExportIdentifier.MatchString(yaraIdentifier(firstNonEmpty(rule.Title, rule.ID))) {
		return refuse("title/id (cannot form a YARA identifier)")
	}
	if tags := rule.Labels["yara.tags"]; tags != "" {
		for _, tag := range strings.Split(tags, ",") {
			if !yaraExportIdentifier.MatchString(tag) {
				return refuse("labels.yara.tags")
			}
		}
	}
	for key := range rule.Labels {
		if strings.HasPrefix(key, "yara.meta.") && !yaraExportIdentifier.MatchString(strings.TrimPrefix(key, "yara.meta.")) {
			return refuse("labels." + key)
		}
	}
	if strings.ContainsAny(rule.Labels["yara.condition"], "\r\n{}") {
		return refuse("labels.yara.condition (must be a single expression)")
	}
	names := make(map[string]bool)
	for i, value := range rule.YARAStrings {
		if !strings.HasPrefix(value.Name, "$") || !yaraExportIdentifier.MatchString(strings.TrimPrefix(value.Name, "$")) || names[value.Name] {
			return refuse(fmt.Sprintf("yaraStrings[%d].name (invalid or duplicated)", i))
		}
		names[value.Name] = true
		if value.Pattern == "" {
			return refuse(fmt.Sprintf("yaraStrings[%d].pattern (empty)", i))
		}
		switch value.Type {
		case "", "text":
		case "hex":
			if !yaraExportHex.MatchString(strings.TrimSpace(value.Pattern)) || value.Nocase || value.Wide || value.ASCII {
				return refuse(fmt.Sprintf("yaraStrings[%d] (only literal hex byte pairs without modifiers)", i))
			}
		case "regex":
			if strings.ContainsAny(value.Pattern, "/\r\n") {
				return refuse(fmt.Sprintf("yaraStrings[%d].pattern (regex delimiter or newline)", i))
			}
		default:
			return refuse(fmt.Sprintf("yaraStrings[%d].type=%q", i, value.Type))
		}
	}
	return nil
}
