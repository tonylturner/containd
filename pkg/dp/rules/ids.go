// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

package rules

// IDSConfig holds native IDS rules that match on normalized DPI events.
// It mirrors the control-plane model but is embedded in snapshots for DP use.
type IDSConfig struct {
	Enabled    bool
	Rules      []IDSRule
	RuleGroups []RuleGroup
}

// RuleGroup is a named set of IDS rules that can be enabled/disabled as a unit.
type RuleGroup struct {
	ID          string
	Name        string
	Description string
	Filter      string
	Enabled     bool
	RuleCount   int
}

// IDSRule is a normalized event rule (mirrors config.IDSRule for DP use).
type IDSRule struct {
	ID          string
	Enabled     *bool
	Title       string
	Description string
	Proto       string // optional quick filter
	Kind        string // optional quick filter
	When        IDSCondition
	Severity    string // low|medium|high|critical
	Message     string
	Labels      map[string]string

	// Multi-format fields
	SourceFormat    string
	Action          string
	SrcAddr         string
	DstAddr         string
	SrcPort         string
	DstPort         string
	ContentMatches  []ContentMatch
	YARAStrings     []YARAString
	References      []string
	CVE             []string
	MITREAttackIDs  []string
	RawSource       string
	ConversionNotes []string
}

// ContentMatch represents a Suricata/Snort content keyword with modifiers.
type ContentMatch struct {
	Pattern  string
	IsHex    bool
	Negate   bool
	Nocase   bool
	Depth    int
	Offset   int
	Distance int
	Within   int
}

// YARAString represents a named string definition in a YARA rule.
type YARAString struct {
	Name    string
	Pattern string
	Type    string // text|hex|regex
	Nocase  bool
	Wide    bool
	ASCII   bool
}

// IDSCondition is a recursive predicate tree over event fields.
type IDSCondition struct {
	All   []IDSCondition
	Any   []IDSCondition
	Not   *IDSCondition
	Field string
	Op    string
	Value any
}

