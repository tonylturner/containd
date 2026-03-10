// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

package ids

import (
	"bytes"
	"fmt"
	"strings"

	"github.com/tonylturner/containd/pkg/cp/config"
)

// ExportSuricataRule converts a containd IDSRule to a Suricata rule string.
// If the rule was originally imported from Suricata and has RawSource, it is
// returned as-is for a lossless round-trip.
func ExportSuricataRule(rule config.IDSRule) (string, error) {
	if rule.SourceFormat == "suricata" && rule.RawSource != "" {
		return rule.RawSource, nil
	}
	return buildSuricataRule(rule), nil
}

// ExportSuricataRules converts multiple IDSRules to Suricata .rules format.
func ExportSuricataRules(rules []config.IDSRule) ([]byte, error) {
	var buf bytes.Buffer
	for _, rule := range rules {
		s, err := ExportSuricataRule(rule)
		if err != nil {
			return nil, err
		}
		buf.WriteString(s)
		buf.WriteString("\n")
	}
	return buf.Bytes(), nil
}

func buildSuricataRule(rule config.IDSRule) string {
	action := firstNonEmpty(rule.Action, "alert")
	proto := firstNonEmpty(rule.Proto, "ip")

	// Map protocol names to Suricata protocol keywords.
	suriProto := mapProtoToSuricata(proto)

	srcAddr := firstNonEmpty(rule.SrcAddr, "any")
	srcPort := firstNonEmpty(rule.SrcPort, "any")
	dstAddr := firstNonEmpty(rule.DstAddr, "any")
	dstPort := firstNonEmpty(rule.DstPort, "any")

	// Build rule options.
	var opts []string
	if rule.Title != "" {
		opts = append(opts, fmt.Sprintf("msg:\"%s\"", escapeSuricataString(rule.Title)))
	}

	// Content matches.
	for _, cm := range rule.ContentMatches {
		opts = append(opts, buildSuricataContent(cm)...)
	}

	// References.
	for _, ref := range rule.References {
		refType, refVal := classifyReference(ref)
		opts = append(opts, fmt.Sprintf("reference:%s,%s", refType, refVal))
	}

	// SID.
	sid := extractSuricataSID(rule.ID)
	opts = append(opts, fmt.Sprintf("sid:%s", sid))

	// Priority from severity.
	if pri := severityToPriority(rule.Severity); pri > 0 {
		opts = append(opts, fmt.Sprintf("priority:%d", pri))
	}

	// Revision.
	opts = append(opts, "rev:1")

	optStr := strings.Join(opts, "; ")
	return fmt.Sprintf("%s %s %s %s -> %s %s (%s;)", action, suriProto, srcAddr, srcPort, dstAddr, dstPort, optStr)
}

func buildSuricataContent(cm config.ContentMatch) []string {
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

func mapProtoToSuricata(proto string) string {
	switch strings.ToLower(proto) {
	case "tcp", "udp", "icmp", "ip":
		return strings.ToLower(proto)
	case "http", "dns", "tls", "ssh", "ftp", "smtp":
		return strings.ToLower(proto)
	case "modbus", "dnp3", "enip":
		return strings.ToLower(proto)
	default:
		return "ip"
	}
}

func escapeSuricataString(s string) string {
	s = strings.ReplaceAll(s, `\`, `\\`)
	s = strings.ReplaceAll(s, `"`, `\"`)
	s = strings.ReplaceAll(s, `;`, `\;`)
	return s
}

func classifyReference(ref string) (string, string) {
	if strings.HasPrefix(ref, "http://") || strings.HasPrefix(ref, "https://") {
		return "url", ref
	}
	if strings.HasPrefix(ref, "CVE-") || strings.HasPrefix(ref, "cve-") {
		return "cve", ref
	}
	return "url", ref
}

func extractSuricataSID(id string) string {
	id = strings.TrimPrefix(id, "suricata-")
	id = strings.TrimPrefix(id, "snort-")
	// If the ID is numeric, use it directly.
	for _, c := range id {
		if c < '0' || c > '9' {
			// Non-numeric; generate a hash-based SID.
			return fmt.Sprintf("%d", simpleHash(id))
		}
	}
	if id == "" {
		return "1000001"
	}
	return id
}

// simpleHash produces a simple numeric hash suitable for a SID.
func simpleHash(s string) uint32 {
	var h uint32 = 2166136261
	for i := 0; i < len(s); i++ {
		h ^= uint32(s[i])
		h *= 16777619
	}
	// Keep in the custom SID range (1000000+).
	return (h % 9000000) + 1000000
}

func severityToPriority(sev string) int {
	switch strings.ToLower(sev) {
	case "critical":
		return 1
	case "high":
		return 2
	case "medium":
		return 3
	case "low":
		return 4
	default:
		return 0
	}
}
