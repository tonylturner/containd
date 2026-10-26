// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

package config

import (
	"fmt"
	"strconv"
	"strings"
)

// ParsePCAPPortRange parses a single port or inclusive port range. An empty
// filter returns 0, 0 without an error.
func ParsePCAPPortRange(value string) (uint16, uint16, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return 0, 0, nil
	}

	parts := strings.Split(value, "-")
	if len(parts) > 2 {
		return 0, 0, invalidPCAPPort(value)
	}
	start, err := parsePCAPPort(parts[0])
	if err != nil {
		return 0, 0, invalidPCAPPort(value)
	}
	end := start
	if len(parts) == 2 {
		end, err = parsePCAPPort(parts[1])
		if err != nil || end < start {
			return 0, 0, invalidPCAPPort(value)
		}
	}
	return start, end, nil
}

func parsePCAPPort(value string) (uint16, error) {
	if value == "" {
		return 0, fmt.Errorf("empty port")
	}
	for _, r := range value {
		if r < '0' || r > '9' {
			return 0, fmt.Errorf("invalid port")
		}
	}
	port, err := strconv.ParseUint(value, 10, 16)
	if err != nil || port == 0 {
		return 0, fmt.Errorf("port out of range")
	}
	return uint16(port), nil
}

func invalidPCAPPort(value string) error {
	return fmt.Errorf("pcap.filter.port invalid %q: expected a port from 1 to 65535 or a range", value)
}
