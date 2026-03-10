// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

// Package ids — external rule source catalog.
//
// These entries describe well-known community rule repositories that users can
// download and import into containd.  No rules are shipped with the binary;
// the catalog only provides metadata and URLs so the user (or a CLI command)
// can fetch them on-demand.
package ids

// RuleSource describes an external rule repository.
type RuleSource struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Description string `json:"description"`
	URL         string `json:"url"`
	Format      string `json:"format"` // suricata|snort|yara|sigma
	License     string `json:"license"`
	LicenseNote string `json:"licenseNote,omitempty"`
}

// BuiltinSources is the default catalog of community/open-source rule sets.
// Users may add their own entries via configuration.
var BuiltinSources = []RuleSource{
	{
		ID:          "et-open",
		Name:        "Emerging Threats Open",
		Description: "Community-maintained Suricata/Snort ruleset for network threat detection.",
		URL:         "https://rules.emergingthreats.net/open/suricata/emerging-all.rules",
		Format:      FormatSuricata,
		License:     "MIT",
	},
	{
		ID:          "snort-community",
		Name:        "Snort Community Rules",
		Description: "Free Snort rules maintained by the Snort community.",
		URL:         "https://www.snort.org/downloads/community/community-rules.tar.gz",
		Format:      FormatSnort,
		License:     "GPL-2.0",
		LicenseNote: "GPL-licensed — not shipped with containd. User downloads and imports at their own discretion.",
	},
	{
		ID:          "yara-community",
		Name:        "YARA-Rules Community",
		Description: "Community collection of YARA rules for malware detection.",
		URL:         "https://github.com/Yara-Rules/rules",
		Format:      FormatYARA,
		License:     "GPL-2.0",
		LicenseNote: "GPL-licensed — not shipped with containd. User downloads and imports at their own discretion.",
	},
	{
		ID:          "sigma-hq",
		Name:        "SigmaHQ Rules",
		Description: "Main Sigma rule repository for generic log-based detection.",
		URL:         "https://github.com/SigmaHQ/sigma",
		Format:      FormatSigma,
		License:     "DRL-1.1",
		LicenseNote: "Detection Rule License — permits use in security products; review DRL-1.1 terms.",
	},
	{
		ID:          "ics-cert-yara",
		Name:        "ICS-CERT YARA Rules",
		Description: "YARA rules published by CISA for ICS-related malware families.",
		URL:         "https://github.com/cisagov/CHIRP/tree/develop/indicators",
		Format:      FormatYARA,
		License:     "CC0-1.0",
	},
}

// GetSource returns the source with the given ID, or nil if not found.
func GetSource(id string) *RuleSource {
	for i := range BuiltinSources {
		if BuiltinSources[i].ID == id {
			return &BuiltinSources[i]
		}
	}
	return nil
}
