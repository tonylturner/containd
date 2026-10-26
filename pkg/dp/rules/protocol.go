// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 containd Authors

package rules

import (
	"fmt"
	"strconv"
	"strings"
)

// ParsePortRange accepts decimal N or N-M, inclusive, within the uint16
// transport port space. In particular, nft syntax is not accepted here.
func ParsePortRange(s string) (lo, hi uint16, err error) {
	a, b, ranged := strings.Cut(s, "-")
	parse := func(v string) (uint16, error) {
		if v == "" || strings.IndexFunc(v, func(r rune) bool { return r < '0' || r > '9' }) >= 0 {
			return 0, fmt.Errorf("invalid decimal port %q", v)
		}
		n, err := strconv.ParseUint(v, 10, 16)
		return uint16(n), err
	}
	lo, err = parse(a)
	if err != nil {
		return 0, 0, err
	}
	hi = lo
	if ranged {
		hi, err = parse(b)
	}
	if err != nil {
		return 0, 0, err
	}
	if lo > hi {
		return 0, 0, fmt.Errorf("reversed port range %q", s)
	}
	return lo, hi, nil
}

// ValidateProtocol validates a rule's layer-4 selector. No selector is
// represented by an empty protocol list, not by an empty protocol name.
func ValidateProtocol(name, port string) error {
	switch name {
	case "tcp", "udp":
		if port != "" {
			_, _, err := ParsePortRange(port)
			return err
		}
	case "icmp":
		if port != "" {
			return fmt.Errorf("icmp does not take a port")
		}
	default:
		return fmt.Errorf("unsupported protocol %q", name)
	}
	return nil
}
