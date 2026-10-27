// SPDX-License-Identifier: Apache-2.0
package httpapi

import (
	"net"
	"strings"

	"github.com/tonylturner/containd/pkg/cp/config"
	"github.com/tonylturner/containd/pkg/dp/rules"
)

// recoveryAddresses returns the stored static addresses recovery restores
// without a reservation. Management can depend on an address that
// containd assigned itself and that a new container's interfaces lack, so
// recovery restores the addresses of the devices its management input
// admits: physical interfaces bound to such a device with static
// addresses that all parse. Only the name, device and addresses are kept:
// no zone (forwarding), gateway (routes), virtual device, bridge
// membership or DHCP. stored is nil with a reservation, which does not
// depend on stored addresses.
func recoveryAddresses(stored *config.Config, input []rules.LocalServiceRule) []config.Interface {
	if stored == nil {
		return nil
	}
	admitted := map[string]bool{}
	for _, rule := range input {
		for _, dev := range rule.Ifaces {
			admitted[dev] = true
		}
	}
	members := map[string]bool{}
	for _, iface := range stored.Interfaces {
		for _, member := range iface.Members {
			members[strings.TrimSpace(member)] = true
		}
	}
	var out []config.Interface
	for _, iface := range stored.Interfaces {
		dev := strings.TrimSpace(iface.Device)
		kind := strings.ToLower(strings.TrimSpace(iface.Type))
		switch {
		case dev == "" || !admitted[dev] || members[dev] || members[strings.TrimSpace(iface.Name)]:
			continue
		case kind != "" && kind != "physical":
			continue
		case strings.EqualFold(strings.TrimSpace(iface.AddressMode), "dhcp") || !staticPrefixes(iface.Addresses):
			continue
		}
		out = append(out, config.Interface{Name: iface.Name, Device: dev, Addresses: append([]string(nil), iface.Addresses...)})
	}
	return out
}

// staticPrefixes reports whether addrs is a non-empty list of CIDR
// addresses, as interface validation accepts them.
func staticPrefixes(addrs []string) bool {
	for _, a := range addrs {
		if _, _, err := net.ParseCIDR(a); err != nil {
			return false
		}
	}
	return len(addrs) > 0
}
