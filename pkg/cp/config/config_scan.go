// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 containd Authors

package config

import (
	"encoding/json"
	"fmt"
	"strings"
)

// ScanSelection selects the traffic the scanning gate intercepts: HTTP on the
// listed destination ports between the listed zone pairs. Include entries
// select, exclude entries win over every include; within an entry every
// populated field must match, and an empty zone list means any zone. Ports
// and addresses are the effective (post-DNAT) destination.
type ScanSelection struct {
	Include      []ScanInclude `json:"include,omitempty"`
	Exclude      []ScanExclude `json:"exclude,omitempty"`
	DownloadMode string        `json:"downloadMode,omitempty"` // hold (default) | stream_tail
	// ICSZones and ICSAssets mark the endpoints that pass unscanned
	// outcomes under a closed fail policy; confirmed malware is still blocked.
	ICSZones  []string `json:"icsZones,omitempty"`
	ICSAssets []string `json:"icsAssets,omitempty"` // asset IDs
}

// ScanInclude selects connections from SourceZones to DestZones on DestPorts
// (decimal ports or N-M ranges, at least one).
type ScanInclude struct {
	SourceZones []string `json:"sourceZones,omitempty"`
	DestZones   []string `json:"destZones,omitempty"`
	DestPorts   []string `json:"destPorts"`
}

// ScanExclude keeps matching connections out of the gate. At least one field
// must be set; Sources and Destinations are CIDRs.
type ScanExclude struct {
	SourceZones  []string `json:"sourceZones,omitempty"`
	DestZones    []string `json:"destZones,omitempty"`
	Sources      []string `json:"sources,omitempty"`
	Destinations []string `json:"destinations,omitempty"`
	DestPorts    []string `json:"destPorts,omitempty"`
}

// Download modes and the default fail policy of the scanning gate.
const (
	ScanDownloadHold       = "hold"
	ScanDownloadStreamTail = "stream_tail"
)

// EffectiveDownloadMode returns the download mode with the default applied.
func (s ScanSelection) EffectiveDownloadMode() string {
	if mode := strings.ToLower(strings.TrimSpace(s.DownloadMode)); mode != "" {
		return mode
	}
	return ScanDownloadHold
}

// EffectiveFailPolicy returns the fail policy with the default applied.
func (a AVConfig) EffectiveFailPolicy() string {
	if policy := strings.ToLower(strings.TrimSpace(a.FailPolicy)); policy != "" {
		return policy
	}
	return "open"
}

// ScanGateEnabled reports whether the scanning gate intercepts anything:
// scanning is on, at least one include entry exists and at least one HTTP
// direction is scanned.
func (a AVConfig) ScanGateEnabled() bool {
	return a.Enabled && len(a.Scan.Include) > 0 && (a.HTTPDownload || a.HTTPUpload)
}

var (
	scanSelectionJSONKeys = []string{"include", "exclude", "downloadMode", "icsZones", "icsAssets"}
	scanIncludeJSONKeys   = []string{"sourceZones", "destZones", "destPorts"}
	scanExcludeJSONKeys   = []string{"sourceZones", "destZones", "sources", "destinations", "destPorts"}
)

// UnmarshalJSON rejects unknown and duplicate scan keys so a misspelt field
// cannot silently widen or narrow the selection. The rest of services.av
// stays lenient.
func (s *ScanSelection) UnmarshalJSON(data []byte) error {
	if isJSONNull(data) {
		return nil
	}
	if _, err := decodeStrictObject(data, scanSelectionJSONKeys); err != nil {
		return fmt.Errorf("services.av.scan: %w", err)
	}
	type scanAlias ScanSelection
	var decoded scanAlias
	if err := json.Unmarshal(data, &decoded); err != nil {
		return fmt.Errorf("services.av.scan: %w", err)
	}
	*s = ScanSelection(decoded)
	return nil
}

// UnmarshalJSON rejects unknown and duplicate include keys.
func (e *ScanInclude) UnmarshalJSON(data []byte) error {
	if isJSONNull(data) {
		return nil
	}
	if _, err := decodeStrictObject(data, scanIncludeJSONKeys); err != nil {
		return fmt.Errorf("include: %w", err)
	}
	type includeAlias ScanInclude
	var decoded includeAlias
	if err := json.Unmarshal(data, &decoded); err != nil {
		return fmt.Errorf("include: %w", err)
	}
	*e = ScanInclude(decoded)
	return nil
}

// UnmarshalJSON rejects unknown and duplicate exclude keys.
func (e *ScanExclude) UnmarshalJSON(data []byte) error {
	if isJSONNull(data) {
		return nil
	}
	if _, err := decodeStrictObject(data, scanExcludeJSONKeys); err != nil {
		return fmt.Errorf("exclude: %w", err)
	}
	type excludeAlias ScanExclude
	var decoded excludeAlias
	if err := json.Unmarshal(data, &decoded); err != nil {
		return fmt.Errorf("exclude: %w", err)
	}
	*e = ScanExclude(decoded)
	return nil
}
