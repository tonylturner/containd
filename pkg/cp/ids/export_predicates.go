// SPDX-License-Identifier: Apache-2.0
package ids

import (
	"encoding/hex"
	"fmt"
	"strings"

	"github.com/tonylturner/containd/pkg/cp/config"
)

// checkRulesFilePredicates is deliberately an allowlist. Native conditions
// operate on decoder events, not the target engine's inspection buffers.
// An option with a similar name is not evidence of equivalent semantics.
func checkRulesFilePredicates(rule config.IDSRule, format string) error {
	refuse := func(predicate string) error {
		return &RuleExportError{RuleID: rule.ID, Predicate: predicate, Format: format}
	}
	if rule.SourceFormat != "" && rule.SourceFormat != FormatNative && rule.SourceFormat != format {
		return refuse(fmt.Sprintf("sourceFormat=%q (cross-format predicates)", rule.SourceFormat))
	}
	if len(rule.ConversionNotes) > 0 || rule.Labels["evaluable"] == "false" {
		return refuse("conversionNotes/evaluable (unrepresented source predicates)")
	}
	switch strings.ToLower(rule.Proto) {
	case "", "ip", "tcp", "udp", "icmp":
	default:
		return &RuleExportError{
			RuleID: rule.ID, Predicate: fmt.Sprintf("proto=%q (application service)", rule.Proto),
			Format: format, protocol: true,
		}
	}
	if rule.Kind != "" {
		return refuse(fmt.Sprintf("kind=%q", rule.Kind))
	}
	if predicate := unsupportedCondition(rule.When, "when"); predicate != "" {
		return refuse(predicate)
	}
	if len(rule.YARAStrings) > 0 {
		return refuse("yaraStrings")
	}
	for _, key := range []string{"yara.condition", "sigma.logsource", "activated_by", "count", "tag"} {
		if rule.Labels[key] != "" {
			return refuse("labels." + key)
		}
	}
	for i, content := range rule.ContentMatches {
		if content.Pattern == "" || strings.ContainsAny(content.Pattern, "\r\n") {
			return refuse(fmt.Sprintf("contentMatches[%d].pattern (empty or multiline)", i))
		}
		if content.IsHex {
			// Only literal byte pairs have established semantics here. Do not
			// reinterpret wildcards or mixed text/hex as literal bytes.
			for _, pair := range strings.Fields(content.Pattern) {
				if _, err := hex.DecodeString(pair); err != nil || len(pair) != 2 {
					return refuse(fmt.Sprintf("contentMatches[%d].pattern (not hex byte pairs)", i))
				}
			}
			if len(strings.Fields(content.Pattern)) == 0 {
				return refuse(fmt.Sprintf("contentMatches[%d].pattern (empty hex)", i))
			}
		} else if strings.Contains(content.Pattern, "|") {
			return refuse(fmt.Sprintf("contentMatches[%d].pattern (literal pipe requires hex encoding)", i))
		}
		if content.Depth < 0 || content.Offset < 0 || content.Within < 0 {
			return refuse(fmt.Sprintf("contentMatches[%d] negative depth/offset/within", i))
		}
	}
	return nil
}

func unsupportedCondition(c config.IDSCondition, path string) string {
	if c.Field != "" || c.Op != "" || c.Value != nil {
		return fmt.Sprintf("%s field=%q op=%q", path, c.Field, c.Op)
	}
	if c.Not != nil {
		if predicate := unsupportedCondition(*c.Not, path+".not"); predicate != "" {
			return predicate
		}
		return path + ".not"
	}
	for _, group := range []struct {
		name     string
		children []config.IDSCondition
	}{{"all", c.All}, {"any", c.Any}} {
		for i, child := range group.children {
			childPath := fmt.Sprintf("%s.%s[%d]", path, group.name, i)
			if predicate := unsupportedCondition(child, childPath); predicate != "" {
				return predicate
			}
		}
		if len(group.children) > 0 {
			return path + "." + group.name
		}
	}
	return ""
}

func checkExportEnabled(rule config.IDSRule, format string) error {
	if rule.Enabled != nil && !*rule.Enabled {
		return &RuleExportError{RuleID: rule.ID, Predicate: "enabled=false", Format: format}
	}
	return nil
}
