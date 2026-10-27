// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 containd Authors

package ics

import "fmt"

// Parsing is the per-protocol treatment of nonconformant content inside a
// frame whose boundary is known. It never changes how a lost frame boundary
// or an integrity fault is handled: both fail closed in enforce scope.
type Parsing string

const (
	// Tolerant evaluates the decoded fields against the rules, passes the
	// content it cannot read, and raises a conformance alert. Default.
	Tolerant Parsing = "tolerant"
	// Strict drops nonconformant content and resets the session in
	// enforce scope, and raises the same conformance alert.
	Strict Parsing = "strict"
)

// EffectiveParsing returns the configured mode for protocol name. An absent
// or empty entry is Tolerant.
func EffectiveParsing(modes map[string]string, name string) Parsing {
	if Parsing(modes[name]) == Strict {
		return Strict
	}
	return Tolerant
}

// ValidateParsing rejects unknown protocols and values other than
// "tolerant" and "strict". An empty value means the default.
func ValidateParsing(modes map[string]string) error {
	for name, mode := range modes {
		if !Supported(name) {
			return unsupportedProtocol("dataplane.dpiIcsParsing: protocol", name)
		}
		switch Parsing(mode) {
		case "", Tolerant, Strict:
		default:
			return fmt.Errorf("dataplane.dpiIcsParsing.%s %q: want tolerant or strict", name, mode)
		}
	}
	return nil
}
