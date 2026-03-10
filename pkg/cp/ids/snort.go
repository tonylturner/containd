// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

package ids

import (
	"github.com/tonylturner/containd/pkg/cp/config"
)

// ParseSnortLine parses a single Snort rule line into a containd IDSRule.
// Snort and Suricata share ~90% of their syntax; the differences are handled
// by the shared parser when sourceFormat is "snort":
//   - IDs are prefixed with "snort-" instead of "suricata-"
//   - Snort-specific keywords (activated_by, count, tag) are stored in Labels
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
