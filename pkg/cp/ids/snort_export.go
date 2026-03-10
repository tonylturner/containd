// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

package ids

import (
	"bytes"
	"fmt"
	"strings"

	"github.com/tonylturner/containd/pkg/cp/config"
)

// ExportSnortRule converts a containd IDSRule to a Snort rule string.
// If the rule was originally imported from Snort and has RawSource, it is
// returned as-is for a lossless round-trip.
func ExportSnortRule(rule config.IDSRule) (string, error) {
	if rule.SourceFormat == "snort" && rule.RawSource != "" {
		return rule.RawSource, nil
	}
	return buildSnortRule(rule), nil
}

// ExportSnortRules converts multiple IDSRules to Snort .rules format.
func ExportSnortRules(rules []config.IDSRule) ([]byte, error) {
	var buf bytes.Buffer
	for _, rule := range rules {
		s, err := ExportSnortRule(rule)
		if err != nil {
			return nil, err
		}
		buf.WriteString(s)
		buf.WriteString("\n")
	}
	return buf.Bytes(), nil
}

func buildSnortRule(rule config.IDSRule) string {
	action := firstNonEmpty(rule.Action, "alert")
	proto := firstNonEmpty(rule.Proto, "ip")
	snortProto := mapProtoToSnort(proto)

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
		contentVal = fmt.Sprintf("|%s|", cm.Pattern)
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
		opts = append(opts, fmt.Sprintf("depth:%d", cm.Depth))
	}
	if cm.Offset > 0 {
		opts = append(opts, fmt.Sprintf("offset:%d", cm.Offset))
	}
	if cm.Distance > 0 {
		opts = append(opts, fmt.Sprintf("distance:%d", cm.Distance))
	}
	if cm.Within > 0 {
		opts = append(opts, fmt.Sprintf("within:%d", cm.Within))
	}
	return opts
}

func mapProtoToSnort(proto string) string {
	switch strings.ToLower(proto) {
	case "tcp", "udp", "icmp", "ip":
		return strings.ToLower(proto)
	default:
		return "ip"
	}
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
