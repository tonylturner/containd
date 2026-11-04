// SPDX-License-Identifier: Apache-2.0

package config

import (
	"fmt"
	"strings"

	"github.com/tonylturner/containd/pkg/dp/enforce"
)

// Every row name is a kernel interface name and must be safe for nftables.
func validateKernelInterfaceName(iface Interface) error {
	if err := enforce.ValidateInterfaceName(iface.Name); err != nil {
		return fmt.Errorf("interface %s kernel name: %w", iface.Name, err)
	}
	return nil
}

// validateDHCPListenIfaceNames checks the listen interfaces of an enabled
// DHCP server that are not configured interfaces: they are kernel device
// names.
func validateDHCPListenIfaceNames(listen []string, ifaces []Interface) error {
	known := map[string]bool{}
	for _, iface := range ifaces {
		known[strings.TrimSpace(iface.Name)] = true
	}
	for _, n := range listen {
		if n = strings.TrimSpace(n); n == "" || known[n] {
			continue
		}
		if err := enforce.ValidateInterfaceName(n); err != nil {
			return fmt.Errorf("dhcp listenIfaces: %w", err)
		}
	}
	return nil
}
