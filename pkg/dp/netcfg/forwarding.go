// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

package netcfg

import (
	"os"
	"strings"

	"github.com/tonylturner/containd/pkg/cp/config"
)

// IPv4ForwardingStatus is the observed IPv4 forwarding state in the current
// network namespace.
type IPv4ForwardingStatus string

const (
	IPv4ForwardingEnabled  IPv4ForwardingStatus = "enabled"
	IPv4ForwardingDisabled IPv4ForwardingStatus = "disabled"
	IPv4ForwardingUnknown  IPv4ForwardingStatus = "unknown"

	ipv4ForwardingSysctl = "/proc/sys/net/ipv4/ip_forward"
)

// ReadIPv4ForwardingStatus reports IPv4 forwarding from the current network
// namespace. This should be called by the engine, which owns the forwarding
// namespace.
func ReadIPv4ForwardingStatus() IPv4ForwardingStatus {
	return readIPv4ForwardingStatus(ipv4ForwardingSysctl)
}

func readIPv4ForwardingStatus(path string) IPv4ForwardingStatus {
	data, err := os.ReadFile(path)
	if err != nil {
		return IPv4ForwardingUnknown
	}
	switch strings.TrimSpace(string(data)) {
	case "1":
		return IPv4ForwardingEnabled
	case "0":
		return IPv4ForwardingDisabled
	default:
		return IPv4ForwardingUnknown
	}
}

// RequiresIPv4Forwarding reports whether the configured interfaces span at
// least two zone-assigned kernel devices, the condition under which netcfg
// enables IPv4 forwarding.
func RequiresIPv4Forwarding(ifaces []config.Interface) bool {
	seen := map[string]struct{}{}
	for _, iface := range ifaces {
		if strings.TrimSpace(iface.Zone) == "" {
			continue
		}
		dev := strings.TrimSpace(iface.Device)
		if dev == "" {
			dev = strings.TrimSpace(iface.Name)
		}
		if dev == "" {
			continue
		}
		seen[dev] = struct{}{}
		if len(seen) >= 2 {
			return true
		}
	}
	return false
}
