// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

package ids

import (
	"fmt"
	"strings"

	"github.com/tonylturner/containd/pkg/cp/config"
)

// ExportSnortRule converts a containd IDSRule to a Snort rule string.
// Equivalent cached source is returned unchanged; stale or corrupt source
// falls through to native export and its preserve-or-refuse checks.
func ExportSnortRule(rule config.IDSRule) (string, error) {
	return exportWithSourceCache(rule, FormatSnort, func(rule config.IDSRule) (string, error) {
		if err := checkRulesFilePredicates(rule, FormatSnort); err != nil {
			return "", err
		}
		return buildSnortRule(rule), nil
	})
}

// ExportSnortRules returns rules text and explicit, commented refusals.
func ExportSnortRules(rules []config.IDSRule) (ExportResult, error) {
	return exportRulesFile(rules, ExportSnortRule)
}

func buildSnortRule(rule config.IDSRule) string {
	action := firstNonEmpty(rule.Action, "alert")
	snortProto := strings.ToLower(firstNonEmpty(rule.Proto, "ip"))

	srcAddr := firstNonEmpty(rule.SrcAddr, "any")
	srcPort := firstNonEmpty(rule.SrcPort, "any")
	dstAddr := firstNonEmpty(rule.DstAddr, "any")
	dstPort := firstNonEmpty(rule.DstPort, "any")

	var opts []string
	if rule.Title != "" {
		opts = append(opts, fmt.Sprintf("msg:\"%s\"", escapeSuricataString(rule.Title)))
	}

	// Content matches.
	for _, cm := range rule.ContentMatches {
		opts = append(opts, buildSnortContent(cm)...)
	}

	// References.
	for _, ref := range rule.References {
		refType, refVal := classifyReference(ref)
		opts = append(opts, fmt.Sprintf("reference:%s,%s", refType, refVal))
	}

	// SID.
	sid := extractSnortSID(rule.ID)
	opts = append(opts, fmt.Sprintf("sid:%s", sid))

	// Priority from severity.
	if pri := severityToPriority(rule.Severity); pri > 0 {
		opts = append(opts, fmt.Sprintf("priority:%d", pri))
	}

	// Revision.
	opts = append(opts, "rev:1")

	// Classtype from labels if present.
	if ct, ok := rule.Labels["classtype"]; ok {
		opts = append(opts, fmt.Sprintf("classtype:%s", ct))
	}

	optStr := strings.Join(opts, "; ")
	return fmt.Sprintf("%s %s %s %s -> %s %s (%s;)", action, snortProto, srcAddr, srcPort, dstAddr, dstPort, optStr)
}

func buildSnortContent(cm config.ContentMatch) []string {
	var opts []string
	var contentVal string
	if cm.IsHex {
		contentVal = fmt.Sprintf("\"|%s|\"", cm.Pattern)
	} else {
		contentVal = fmt.Sprintf("\"%s\"", escapeSuricataString(cm.Pattern))
	}
	if cm.Negate {
		contentVal = "!" + contentVal
	}
	opts = append(opts, "content:"+contentVal)

	if cm.Nocase {
		opts = append(opts, "nocase")
	}
	if cm.Depth > 0 {
		opts = append(opts, fmt.Sprintf("depth %d", cm.Depth))
	}
	if cm.Offset > 0 {
		opts = append(opts, fmt.Sprintf("offset %d", cm.Offset))
	}
	if cm.Distance != 0 {
		opts = append(opts, fmt.Sprintf("distance %d", cm.Distance))
	}
	if cm.Within > 0 {
		opts = append(opts, fmt.Sprintf("within %d", cm.Within))
	}
	// Snort 3 modifiers belong to the content option, not separate options.
	return []string{strings.Join(opts, ", ")}
}

func extractSnortSID(id string) string {
	id = strings.TrimPrefix(id, "snort-")
	id = strings.TrimPrefix(id, "suricata-")
	for _, c := range id {
		if c < '0' || c > '9' {
			return fmt.Sprintf("%d", simpleHash(id))
		}
	}
	if id == "" {
		return "1000001"
	}
	return id
}
