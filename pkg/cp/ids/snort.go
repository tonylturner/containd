// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

package ids

import (
	"strings"

	"github.com/tonylturner/containd/pkg/cp/config"
)

// ParseSnortLine parses a single Snort rule line into a containd IDSRule.
// Snort and Suricata share ~90% of their syntax; the differences are handled
// by the shared parser when sourceFormat is "snort":
//   - IDs are prefixed with "snort-" instead of "suricata-"
//   - Snort-specific keywords (activated_by, count, tag) are stored in Labels
//   - Snort 3 comma-separated content modifiers are normalized to separate options
func ParseSnortLine(line string) (config.IDSRule, error) {
	return parseSuricataSnortLine(line, "snort")
}

// ConvertSnortFile parses all rules from a Snort .rules file (byte content).
func ConvertSnortFile(data []byte) ([]config.IDSRule, error) {
	return convertRulesData(data, "snort")
}

// ConvertSnortFiles parses rules from multiple Snort .rules files.
func ConvertSnortFiles(paths []string) ([]config.IDSRule, error) {
	return convertRulesFiles(paths, "snort")
}

// normalizeSnortContentOptions makes Snort 3 modifiers visible to both content
// extraction and condition conversion. Unknown modifiers remain options, so
// they receive the same conversion notes as unknown Snort 2 options.
func normalizeSnortContentOptions(opts [][2]string) [][2]string {
	var normalized [][2]string
	for _, opt := range opts {
		idx := findOptionDelimiter(opt[1], ',')
		if opt[0] != "content" || idx < 0 {
			normalized = append(normalized, opt)
			continue
		}
		content := strings.TrimSpace(opt[1][:idx])
		pattern := strings.TrimSpace(strings.TrimPrefix(content, "!"))
		if len(pattern) < 2 || pattern[0] != '"' || pattern[len(pattern)-1] != '"' {
			normalized = append(normalized, opt)
			continue
		}
		normalized = append(normalized, [2]string{"content", content})
		remaining := opt[1][idx+1:]
		for remaining != "" {
			idx = findOptionDelimiter(remaining, ',')
			var modifier string
			if idx < 0 {
				modifier, remaining = remaining, ""
			} else {
				modifier, remaining = remaining[:idx], remaining[idx+1:]
			}
			modifier = strings.TrimSpace(modifier)
			if modifier == "" {
				continue
			}
			keyword, value := modifier, ""
			if space := strings.IndexAny(modifier, " \t\r\n"); space >= 0 {
				keyword, value = modifier[:space], strings.TrimSpace(modifier[space+1:])
			}
			normalized = append(normalized, [2]string{keyword, value})
		}
	}
	return normalized
}
