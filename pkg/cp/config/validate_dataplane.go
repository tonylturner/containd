// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

package config

import (
	"errors"
	"fmt"
	"strings"

	"github.com/tonylturner/containd/pkg/dp/enforce"
	"github.com/tonylturner/containd/pkg/dp/ics"
)

func validateDataPlane(dp DataPlaneConfig) error {
	if err := ics.ValidateToggles(dp.DPIICSProtocols); err != nil {
		return err
	}
	if err := ics.ValidateParsing(dp.DPIICSParsing); err != nil {
		return err
	}
	if err := validateDomainExclusions(dp.DPIExclusions); err != nil {
		return err
	}
	if m := dp.DPIMode; m != "" && m != "learn" && m != "enforce" {
		return fmt.Errorf("dataplane.dpiMode invalid %q (want learn or enforce)", m)
	}
	for _, name := range dp.CaptureInterfaces {
		if name == "" {
			return errors.New("dataplane.captureInterfaces cannot include empty name")
		}
	}
	if t := dp.EnforceTable; t != "" {
		if err := enforce.ValidateTableName(t); err != nil {
			return fmt.Errorf("dataplane.enforceTable: %w", err)
		}
	}
	return nil
}

func validatePCAP(p PCAPConfig) error {
	if err := validatePCAPInterfaces(p); err != nil {
		return err
	}
	if err := validatePCAPLimits(p); err != nil {
		return err
	}
	if err := validatePCAPMode(p.Mode); err != nil {
		return err
	}
	if err := validatePCAPFilter(p.Filter); err != nil {
		return err
	}
	return validatePCAPForwardTargets(p.ForwardTargets)
}

// ValidatePCAPConfig validates PCAP capture settings independently of the
// remainder of the appliance configuration.
func ValidatePCAPConfig(p PCAPConfig) error {
	return validatePCAP(p)
}

func validatePCAPInterfaces(p PCAPConfig) error {
	for _, name := range p.Interfaces {
		if strings.TrimSpace(name) == "" {
			return errors.New("pcap.interfaces cannot include empty name")
		}
	}
	for _, name := range p.Zones {
		if strings.TrimSpace(name) == "" {
			return errors.New("pcap.zones cannot include empty name")
		}
	}
	if p.Enabled && len(p.Interfaces) == 0 && len(p.Zones) == 0 {
		return errors.New("pcap.enabled requires at least one interface or zone")
	}
	return nil
}

func validatePCAPLimits(p PCAPConfig) error {
	if p.Snaplen < 0 {
		return errors.New("pcap.snaplen must be >= 0")
	}
	if p.MaxSizeMB < 0 {
		return errors.New("pcap.maxSizeMB must be >= 0")
	}
	if p.MaxFiles < 0 {
		return errors.New("pcap.maxFiles must be >= 0")
	}
	if p.BufferMB < 0 {
		return errors.New("pcap.bufferMB must be >= 0")
	}
	if p.RotateSeconds < 0 {
		return errors.New("pcap.rotateSeconds must be >= 0")
	}
	return nil
}

func validatePCAPMode(mode string) error {
	if mode != "" && mode != "rolling" && mode != "once" {
		return fmt.Errorf("pcap.mode invalid %q", mode)
	}
	return nil
}

func validatePCAPFilter(filter PCAPFilter) error {
	proto := strings.ToLower(strings.TrimSpace(filter.Proto))
	if proto != "" && proto != "any" && proto != "tcp" && proto != "udp" && proto != "icmp" {
		return fmt.Errorf("pcap.filter.proto invalid %q", filter.Proto)
	}
	if strings.TrimSpace(filter.Port) != "" {
		if proto == "icmp" {
			return errors.New("pcap.filter.port cannot be used with proto icmp")
		}
		if _, _, err := ParsePCAPPortRange(filter.Port); err != nil {
			return err
		}
	}
	return nil
}

func validatePCAPForwardTargets(targets []PCAPForwardTarget) error {
	for _, t := range targets {
		if err := validatePCAPForwardTarget(t); err != nil {
			return err
		}
	}
	return nil
}

func validatePCAPForwardTarget(t PCAPForwardTarget) error {
	if strings.TrimSpace(t.Interface) == "" {
		return errors.New("pcap.forwardTargets.interface cannot be empty")
	}
	if t.Enabled {
		if strings.TrimSpace(t.Host) == "" {
			return errors.New("pcap.forwardTargets.host is required when enabled")
		}
		if t.Port <= 0 || t.Port > 65535 {
			return fmt.Errorf("pcap.forwardTargets.port out of range: %d", t.Port)
		}
	}
	if t.Proto != "" && t.Proto != "tcp" && t.Proto != "udp" {
		return fmt.Errorf("pcap.forwardTargets.proto invalid %q", t.Proto)
	}
	return nil
}

// ValidateDataPlaneConfig validates settings accepted by the internal engine API.
func ValidateDataPlaneConfig(dp DataPlaneConfig) error { return validateDataPlane(dp) }
