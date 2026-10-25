// SPDX-License-Identifier: Apache-2.0
//go:build linux

package netcfg

import (
	"net"
	"strings"
)

// parseAddressCIDR preserves the host IP. net.ParseCIDR's second result is
// masked for routes, and must not be used unchanged for interface addresses.
func parseAddressCIDR(cidr string) (*net.IPNet, error) {
	ip, n, err := net.ParseCIDR(strings.TrimSpace(cidr))
	if err != nil {
		return nil, err
	}
	n.IP = ip
	return n, nil
}
