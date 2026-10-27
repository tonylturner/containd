// SPDX-License-Identifier: Apache-2.0

// Package ics defines the industrial protocol vocabulary shared by control
// plane validation and data plane consumers.
package ics

import (
	"fmt"
	"strings"
)

const SupportedNames = "modbus, dnp3, iec104, cip"

func Supported(name string) bool {
	switch name {
	case "modbus", "dnp3", "iec104", "cip":
		return true
	}
	return false
}

// Learnable excludes IEC104: it stays visible in telemetry but must never
// produce automatically learned permissive rules.
func Learnable(name string) bool {
	return Supported(name) && name != "iec104"
}

// Removed identifies obsolete semantic references, not generic numeric ports
// or historical telemetry. IT and generic IDS protocols remain valid.
func Removed(name string) bool {
	switch strings.ToLower(strings.TrimSpace(name)) {
	case "s7comm", "s7", "mms", "iec61850", "goose", "bacnet", "opcua":
		return true
	}
	return false
}

func ValidateRule(id, name string) error {
	if name != "" && !Supported(name) {
		return fmt.Errorf("rule %s ics protocol %q is not supported; supported: %s", id, name, SupportedNames)
	}
	return nil
}

func ValidateToggles(toggles map[string]bool) error {
	for name := range toggles {
		if !Supported(name) {
			return fmt.Errorf("dataplane.dpiIcsProtocols: protocol %q is not supported; supported: %s", name, SupportedNames)
		}
	}
	return nil
}

func ValidateIDS(id, name string) error {
	if Removed(name) {
		return fmt.Errorf("ids rule %s proto %q is not supported; supported: %s", id, name, SupportedNames)
	}
	return nil
}

func ValidateSignature(id, name string) error {
	if Removed(name) {
		return fmt.Errorf("signature %s protocol %q is not supported; supported: %s", id, name, SupportedNames)
	}
	return nil
}
