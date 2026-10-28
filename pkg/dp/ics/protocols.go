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

// Removed identifies obsolete industrial labels, including the non-emitted
// enip label for CIP, not generic numeric ports
// or historical telemetry. IT and generic IDS protocols remain valid.
func Removed(name string) bool {
	switch strings.ToLower(strings.TrimSpace(name)) {
	case "s7comm", "s7", "mms", "iec61850", "goose", "bacnet", "opcua", "enip":
		return true
	}
	return false
}

func ValidateRule(id, name string) error {
	if name != "" && !Supported(name) {
		return unsupportedProtocol("rule "+id+" ics protocol", name)
	}
	return nil
}

func ValidateToggles(toggles map[string]bool) error {
	for name := range toggles {
		if !Supported(name) {
			return unsupportedProtocol("dataplane.dpiIcsProtocols: protocol", name)
		}
	}
	return nil
}

func ValidateIDS(id, name string) error {
	if Removed(name) {
		return unsupportedProtocol("ids rule "+id+" proto", name)
	}
	return nil
}

func ValidateSignature(id, name string) error {
	if Removed(name) {
		return unsupportedProtocol("signature "+id+" protocol", name)
	}
	return nil
}

func unsupportedProtocol(scope, name string) error {
	if strings.EqualFold(strings.TrimSpace(name), "enip") {
		return fmt.Errorf(`%s %q: EtherNet/IP is decoded as "cip"; match encapsulation commands with enip_command`, scope, name)
	}
	return fmt.Errorf("%s %q is not supported; supported: %s", scope, name, SupportedNames)
}
