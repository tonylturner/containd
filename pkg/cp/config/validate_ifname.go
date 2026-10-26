// SPDX-License-Identifier: Apache-2.0

package config

import (
	"fmt"
	"strings"

	"github.com/tonylturner/containd/pkg/dp/enforce"
)

// Kernel interface names reach nftables, so configuration takes only the
// names the firewall can write there (enforce.ValidateInterfaceName): the
// device an interface is bound to, the name of an interface without one,
// which is its kernel name, and DHCP listen interfaces that name a kernel
// device directly.

// validateKernelInterfaceName checks the kernel name of one interface.
func validateKernelInterfaceName(iface Interface) error {
	if strings.TrimSpace(iface.Device) != "" {
		if err := enforce.ValidateInterfaceName(iface.Device); err != nil {
			return fmt.Errorf("interface %s device: %w", iface.Name, err)
		}
		return nil
	}
	if err := enforce.ValidateInterfaceName(iface.Name); err != nil {
		return fmt.Errorf("interface %s has no device, so its name is its kernel name: %w", iface.Name, err)
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
		known[strings.TrimSpace(iface.Device)] = true
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
