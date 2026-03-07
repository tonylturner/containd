// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

package rules

// IDSConfig holds native IDS rules that match on normalized DPI events.
// It mirrors the control-plane model but is embedded in snapshots for DP use.
type IDSConfig struct {
	Enabled bool
	Rules   []IDSRule
}

// IDSRule is a Sigma-like event rule.
type IDSRule struct {
	ID          string
	Title       string
	Description string
	Proto       string // optional quick filter
	Kind        string // optional quick filter
	When        IDSCondition
	Severity    string // low|medium|high|critical
	Message     string
	Labels      map[string]string
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

