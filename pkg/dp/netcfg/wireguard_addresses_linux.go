// SPDX-License-Identifier: Apache-2.0
//go:build linux

package netcfg

import (
	"fmt"
	"net"
	"strings"

	"golang.org/x/sys/unix"
)

// WireGuard owns its interface's IPv4 addresses. Every read/remove/add must
// complete before the service owner can acknowledge the requested configuration.
func replaceWireGuardAddresses(index int, cidr string,
	list func(int, int) ([]*net.IPNet, error),
	remove, add func(int, *net.IPNet) error,
) error {
	var desired *net.IPNet
	if strings.TrimSpace(cidr) != "" {
		var err error
		desired, err = parseAddressCIDR(cidr)
		if err != nil || desired == nil {
			return fmt.Errorf("invalid addressCIDR %q", cidr)
		}
	}
	addresses, err := list(index, unix.AF_INET)
	if err != nil {
		return fmt.Errorf("list addresses: %w", err)
	}
	for _, address := range addresses {
		if err := remove(index, address); err != nil {
			return fmt.Errorf("remove address: %w", err)
		}
	}
	if desired != nil {
		if err := add(index, desired); err != nil {
			return fmt.Errorf("add address: %w", err)
		}
	}
	return nil
}
