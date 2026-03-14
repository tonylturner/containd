// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

package ids

import (
	"fmt"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/tonylturner/containd/pkg/cp/config"
)

// Supported import/export format names.
const (
	FormatNative   = "native"
	FormatSuricata = "suricata"
	FormatSnort    = "snort"
	FormatYARA     = "yara"
	FormatSigma    = "sigma"
)

// Import is an alias for ImportRules.
func Import(format string, data []byte) ([]config.IDSRule, error) {
	return ImportRules(data, format)
}

// ImportRules parses raw rule data in the given format and returns normalized IDSRules.
func ImportRules(data []byte, format string) ([]config.IDSRule, error) {
	switch strings.ToLower(format) {
	case FormatSuricata:
		return ConvertSuricataFile(data)
	case FormatSnort:
		return ConvertSnortFile(data)
	case FormatYARA:
		return ConvertYARAFile(data)
	case FormatSigma:
		return ConvertSigmaFile(data)
	default:
		return nil, fmt.Errorf("unsupported import format: %s", format)
	}
}

// Export is an alias for ExportRules.
func Export(format string, rules []config.IDSRule) ([]byte, error) {
	return ExportRules(rules, format)
}

// ExportRules converts normalized IDSRules to the specified output format.
func ExportRules(rules []config.IDSRule, format string) ([]byte, error) {
	switch strings.ToLower(format) {
	case FormatSuricata:
		return ExportSuricataRules(rules)
	case FormatSnort:
		return ExportSnortRules(rules)
	case FormatYARA:
		return ExportYARARules(rules)
	case FormatSigma:
		return ExportSigmaRules(rules)
	default:
		return nil, fmt.Errorf("unsupported export format: %s", format)
	}
}

// DetectFormat attempts to identify the rule format from a filename and/or
// file content.  Returns one of the Format* constants, or "" if unknown.
func DetectFormat(filename string, data []byte) string {
	// Try extension first.
	ext := strings.ToLower(filepath.Ext(filename))
	switch ext {
	case ".yml", ".yaml":
		return FormatSigma
	case ".yar", ".yara":
		return FormatYARA
	case ".rules":
		return FormatSuricata
	}

	// Fall back to content heuristics.
	s := string(data)
	if reYARARule.MatchString(s) {
		return FormatYARA
	}
	if strings.Contains(s, "detection:") || strings.Contains(s, "logsource:") {
		return FormatSigma
	}
	if reSuricataRule.MatchString(s) {
		return FormatSuricata
	}
	return ""
}

var (
	reYARARule     = regexp.MustCompile(`(?m)^\s*(?:private\s+|global\s+)*rule\s+\w+`)
	reSuricataRule = regexp.MustCompile(`(?m)^\s*(?:alert|drop|pass|reject)\s+(?:tcp|udp|icmp|ip|http|dns|tls|ssh|ftp|smtp|modbus|dnp3|enip)\s+`)
)
