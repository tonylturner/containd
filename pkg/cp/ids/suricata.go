// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

package ids

import (
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/tonylturner/containd/pkg/cp/config"
)

// Well-known port-to-protocol mappings for ICS/OT enrichment.
var portProtoMap = map[string]string{
	"502":   "modbus",
	"44818": "enip",
	"2222":  "enip",
	"20000": "dnp3",
	"4840":  "opcua",
	"102":   "s7comm",
	"47808": "bacnet",
	"18245": "goose",
	"161":   "snmp",
	"162":   "snmp",
	"53":    "dns",
	"443":   "tls",
	"80":    "http",
	"22":    "ssh",
	"3389":  "rdp",
	"445":   "smb",
	"123":   "ntp",
}

// suricataPriorityMap maps Suricata/Snort numeric priority to containd severity.
var suricataPriorityMap = map[int]string{
	1: "critical",
	2: "high",
	3: "medium",
	4: "low",
}

// classtypeSeverityMap maps common classtypes to default severity when no
// explicit priority is set.
var classtypeSeverityMap = map[string]string{
	"trojan-activity":          "high",
	"attempted-admin":          "high",
	"attempted-user":           "medium",
	"shellcode-detect":         "critical",
	"successful-admin":         "critical",
	"successful-user":          "high",
	"web-application-attack":   "high",
	"policy-violation":         "medium",
	"bad-unknown":              "medium",
	"misc-activity":            "low",
	"not-suspicious":           "low",
	"protocol-command-decode":  "medium",
	"network-scan":             "medium",
	"denial-of-service":        "high",
	"attempted-dos":            "medium",
	"attempted-recon":          "low",
	"successful-recon-limited": "medium",
	"successful-recon-largescale": "high",
}

// ParseSuricataLine parses a single Suricata rule line into a containd IDSRule.
// Blank lines and comment lines (starting with #) return an empty rule and nil error
// with the ID field empty, which callers should skip.
func ParseSuricataLine(line string) (config.IDSRule, error) {
	return parseSuricataSnortLine(line, "suricata")
}

// ConvertSuricataFile parses all rules from a Suricata .rules file (byte content).
func ConvertSuricataFile(data []byte) ([]config.IDSRule, error) {
	return convertRulesData(data, "suricata")
}

// ConvertSuricataFiles parses rules from multiple Suricata .rules files.
func ConvertSuricataFiles(paths []string) ([]config.IDSRule, error) {
	return convertRulesFiles(paths, "suricata")
}

// parseSuricataSnortLine is the shared parser for both Suricata and Snort rules.
func parseSuricataSnortLine(line, sourceFormat string) (config.IDSRule, error) {
	trimmed := strings.TrimSpace(line)

	// Skip blank lines and comments.
	if trimmed == "" || strings.HasPrefix(trimmed, "#") {
		return config.IDSRule{}, nil
	}

	// Find the options section in parentheses.
	optStart := strings.Index(trimmed, "(")
	optEnd := strings.LastIndex(trimmed, ")")
	if optStart < 0 || optEnd < 0 || optEnd <= optStart {
		return config.IDSRule{}, fmt.Errorf("malformed rule: missing options parentheses")
	}

	header := strings.TrimSpace(trimmed[:optStart])
	optionsRaw := trimmed[optStart+1 : optEnd]

	// Parse header: action protocol src_addr src_port direction dst_addr dst_port
	hParts := strings.Fields(header)
	if len(hParts) < 7 {
		return config.IDSRule{}, fmt.Errorf("malformed rule header: expected at least 7 fields, got %d", len(hParts))
	}

	action := strings.ToLower(hParts[0])
	protocol := strings.ToLower(hParts[1])
	srcAddr := hParts[2]
	srcPort := hParts[3]
	// hParts[4] is direction (-> or <>)
	dstAddr := hParts[5]
	dstPort := hParts[6]

	// Parse options.
	opts := parseOptions(optionsRaw)

	rule := config.IDSRule{
		Labels: map[string]string{},
	}

	// SourceFormat and RawSource.
	rule.SourceFormat = sourceFormat
	rule.RawSource = trimmed
	rule.Action = action

	// Network fields.
	rule.SrcAddr = srcAddr
	rule.DstAddr = dstAddr
	rule.SrcPort = srcPort
	rule.DstPort = dstPort

	// Protocol header -> Proto field.
	if protocol != "ip" {
		rule.Proto = protocol
	}

	// Map well-known ports to Proto if not already set from protocol header
	// (e.g., protocol=tcp but dst port=502 -> modbus).
	if rule.Proto == "tcp" || rule.Proto == "udp" || rule.Proto == "" {
		if p, ok := portProtoMap[dstPort]; ok {
			rule.Proto = p
		} else if p, ok := portProtoMap[srcPort]; ok {
			rule.Proto = p
		}
	}

	// Extract standard option keywords.
	prefix := "suricata-"
	if sourceFormat == "snort" {
		prefix = "snort-"
	}

	if sid := optVal(opts, "sid"); sid != "" {
		rule.ID = prefix + sid
	}

	if msg := optVal(opts, "msg"); msg != "" {
		// msg values are typically quoted.
		rule.Title = unquote(msg)
		rule.Message = rule.Title
	}

	// Severity: explicit priority takes precedence, then classtype defaults.
	if pri := optVal(opts, "priority"); pri != "" {
		if n, err := strconv.Atoi(strings.TrimSpace(pri)); err == nil {
			if sev, ok := suricataPriorityMap[n]; ok {
				rule.Severity = sev
			}
		}
	}

	// Classtype -> label and fallback severity.
	if ct := optVal(opts, "classtype"); ct != "" {
		rule.Labels["classtype"] = ct
		if rule.Severity == "" {
			if sev, ok := classtypeSeverityMap[ct]; ok {
				rule.Severity = sev
			}
		}
	}

	// Rev.
	if rev := optVal(opts, "rev"); rev != "" {
		rule.Labels["rev"] = rev
	}

	// References.
	for _, v := range optVals(opts, "reference") {
		rule.References = append(rule.References, strings.TrimSpace(v))
	}

	// Metadata: parse key-value pairs, extract CVE and MITRE ATT&CK IDs.
	for _, v := range optVals(opts, "metadata") {
		for _, item := range strings.Split(v, ",") {
			item = strings.TrimSpace(item)
			if item == "" {
				continue
			}
			lower := strings.ToLower(item)
			if strings.HasPrefix(lower, "cve ") || strings.HasPrefix(lower, "cve_") {
				cve := strings.TrimSpace(item[4:])
				rule.CVE = append(rule.CVE, cve)
			} else if strings.HasPrefix(lower, "mitre_attack_") || strings.HasPrefix(lower, "attack.") {
				rule.MITREAttackIDs = append(rule.MITREAttackIDs, item)
			} else {
				rule.Labels["metadata."+item] = ""
			}
		}
	}

	// Content keywords -> ContentMatches.
	rule.ContentMatches = parseContentMatches(opts)

	// Snort-specific keywords stored in labels.
	if sourceFormat == "snort" {
		for _, kw := range []string{"activated_by", "count", "tag"} {
			if v := optVal(opts, kw); v != "" {
				rule.Labels[kw] = v
			}
		}
	}

	// Build When conditions from content matches that can map to DPI fields.
	rule.When = buildWhenFromOptions(opts, protocol)

	// Generate ConversionNotes for anything we couldn't fully map.
	rule.ConversionNotes = buildConversionNotes(opts, protocol)

	// Fallback ID if no sid was present.
	if rule.ID == "" {
		if rule.Title != "" {
			rule.ID = prefix + slugify(rule.Title)
		} else {
			return config.IDSRule{}, fmt.Errorf("rule has no sid or msg for identification")
		}
	}

	return rule, nil
}

// parseOptions splits the Suricata/Snort options section into keyword-value pairs.
// Returns a slice of [keyword, value] pairs preserving order (some keywords repeat).
func parseOptions(raw string) [][2]string {
	var opts [][2]string
	// Options are semicolon-delimited. Values may contain escaped semicolons.
	remaining := raw
	for remaining != "" {
		remaining = strings.TrimSpace(remaining)
		if remaining == "" {
			break
		}
		// Find next unescaped semicolon.
		idx := findUnescapedSemicolon(remaining)
		var part string
		if idx < 0 {
			part = remaining
			remaining = ""
		} else {
			part = remaining[:idx]
			remaining = remaining[idx+1:]
		}
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		// Split on first colon to separate keyword from value.
		if colonIdx := strings.Index(part, ":"); colonIdx >= 0 {
			kw := strings.TrimSpace(part[:colonIdx])
			val := strings.TrimSpace(part[colonIdx+1:])
			opts = append(opts, [2]string{kw, val})
		} else {
			// Keyword-only option (e.g., nocase, rawbytes).
			opts = append(opts, [2]string{part, ""})
		}
	}
	return opts
}

func findUnescapedSemicolon(s string) int {
	for i := 0; i < len(s); i++ {
		if s[i] == '\\' {
			i++ // skip escaped character
			continue
		}
		if s[i] == ';' {
			return i
		}
	}
	return -1
}

// optVal returns the first value for the given keyword.
func optVal(opts [][2]string, keyword string) string {
	for _, o := range opts {
		if o[0] == keyword {
			return o[1]
		}
	}
	return ""
}

// optVals returns all values for the given keyword.
func optVals(opts [][2]string, keyword string) []string {
	var out []string
	for _, o := range opts {
		if o[0] == keyword {
			out = append(out, o[1])
		}
	}
	return out
}

// unquote removes surrounding double quotes from a string if present.
func unquote(s string) string {
	s = strings.TrimSpace(s)
	if len(s) >= 2 && s[0] == '"' && s[len(s)-1] == '"' {
		return s[1 : len(s)-1]
	}
	return s
}

// parseContentMatches extracts content keywords and their modifiers from the
// options list and returns ContentMatch structs.
func parseContentMatches(opts [][2]string) []config.ContentMatch {
	var matches []config.ContentMatch
	var current *config.ContentMatch

	for _, o := range opts {
		kw, val := o[0], o[1]
		switch kw {
		case "content":
			// Flush previous match.
			if current != nil {
				matches = append(matches, *current)
			}
			cm := config.ContentMatch{}
			// Check for negation (! prefix before quotes).
			val = strings.TrimSpace(val)
			if strings.HasPrefix(val, "!") {
				cm.Negate = true
				val = val[1:]
			}
			val = unquote(val)
			// Check for hex content: |DE AD BE EF|.
			if strings.HasPrefix(val, "|") && strings.HasSuffix(val, "|") {
				cm.IsHex = true
				cm.Pattern = val[1 : len(val)-1]
			} else {
				cm.Pattern = val
			}
			current = &cm

		case "nocase":
			if current != nil {
				current.Nocase = true
			}
		case "depth":
			if current != nil {
				if n, err := strconv.Atoi(strings.TrimSpace(val)); err == nil {
					current.Depth = n
				}
			}
		case "offset":
			if current != nil {
				if n, err := strconv.Atoi(strings.TrimSpace(val)); err == nil {
					current.Offset = n
				}
			}
		case "distance":
			if current != nil {
				if n, err := strconv.Atoi(strings.TrimSpace(val)); err == nil {
					current.Distance = n
				}
			}
		case "within":
			if current != nil {
				if n, err := strconv.Atoi(strings.TrimSpace(val)); err == nil {
					current.Within = n
				}
			}
		}
	}

	// Flush last match.
	if current != nil {
		matches = append(matches, *current)
	}

	return matches
}

// buildWhenFromOptions generates IDSCondition trees from options that can map
// to DPI-inspectable fields (e.g., HTTP URI content, protocol-specific fields).
func buildWhenFromOptions(opts [][2]string, protocol string) config.IDSCondition {
	var conds []config.IDSCondition

	// Check for http_uri, http_header, etc. sticky buffers following content.
	var lastContent string
	for _, o := range opts {
		kw, val := o[0], o[1]
		switch kw {
		case "content":
			lastContent = unquote(val)
		case "http_uri", "http.uri":
			if lastContent != "" {
				conds = append(conds, config.IDSCondition{
					Field: "attr.http_uri",
					Op:    "contains",
					Value: lastContent,
				})
			}
		case "http_header", "http.header":
			if lastContent != "" {
				conds = append(conds, config.IDSCondition{
					Field: "attr.http_header",
					Op:    "contains",
					Value: lastContent,
				})
			}
		case "http_method", "http.method":
			if lastContent != "" {
				conds = append(conds, config.IDSCondition{
					Field: "attr.http_method",
					Op:    "equals",
					Value: lastContent,
				})
			}
		case "dns_query", "dns.query":
			if lastContent != "" {
				conds = append(conds, config.IDSCondition{
					Field: "attr.dns_query",
					Op:    "contains",
					Value: lastContent,
				})
			}
		case "tls_sni", "tls.sni":
			if lastContent != "" {
				conds = append(conds, config.IDSCondition{
					Field: "attr.tls_sni",
					Op:    "contains",
					Value: lastContent,
				})
			}
		}
	}

	if len(conds) == 0 {
		return config.IDSCondition{}
	}
	if len(conds) == 1 {
		return conds[0]
	}
	return config.IDSCondition{All: conds}
}

// buildConversionNotes returns notes about options that could not be fully
// mapped to containd rule semantics.
func buildConversionNotes(opts [][2]string, protocol string) []string {
	var notes []string
	unsupported := map[string]bool{}
	for _, o := range opts {
		kw := o[0]
		switch kw {
		// Well-known and fully handled keywords.
		case "msg", "sid", "rev", "classtype", "priority", "reference",
			"metadata", "content", "nocase", "depth", "offset",
			"distance", "within", "flow", "threshold", "flowbits",
			"http_uri", "http.uri", "http_header", "http.header",
			"http_method", "http.method", "dns_query", "dns.query",
			"tls_sni", "tls.sni", "activated_by", "count", "tag":
			continue
		default:
			if !unsupported[kw] {
				unsupported[kw] = true
				notes = append(notes, fmt.Sprintf("keyword %q not fully mapped", kw))
			}
		}
	}
	return notes
}

// convertRulesData parses raw rule file content.
func convertRulesData(data []byte, format string) ([]config.IDSRule, error) {
	lines := strings.Split(string(data), "\n")
	var rules []config.IDSRule
	for i, line := range lines {
		rule, err := parseSuricataSnortLine(line, format)
		if err != nil {
			return nil, fmt.Errorf("line %d: %w", i+1, err)
		}
		if rule.ID == "" {
			continue // blank or comment
		}
		rules = append(rules, rule)
	}
	return rules, nil
}

// convertRulesFiles parses rules from multiple files.
func convertRulesFiles(paths []string, format string) ([]config.IDSRule, error) {
	var all []config.IDSRule
	for _, p := range paths {
		data, err := os.ReadFile(p)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", p, err)
		}
		rules, err := convertRulesData(data, format)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", p, err)
		}
		all = append(all, rules...)
	}
	return all, nil
}
