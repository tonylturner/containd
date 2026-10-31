// SPDX-License-Identifier: Apache-2.0
package config

import (
	"fmt"
	"net/netip"
)

func validateForwardListenAddress(pf PortForward) error {
	if pf.ListenAddress == "" {
		return nil
	}
	a, err := netip.ParseAddr(pf.ListenAddress)
	if err != nil || !a.Is4() {
		return fmt.Errorf("port-forward %s listenAddress must be an IPv4 address: %q", pf.ID, pf.ListenAddress)
	}
	return nil
}

func validateViaForwards(f FirewallConfig) error {
	known := map[string]bool{}
	for _, forward := range f.NAT.PortForwards {
		known[forward.ID] = true
	}
	for _, rule := range f.Rules {
		for _, id := range rule.ViaForwards {
			if id == "" || !known[id] {
				return fmt.Errorf("rule %s viaForwards references unknown port forward %q", rule.ID, id)
			}
		}
	}
	return nil
}

func validateIPv4RoutingPrefix(field, value string) error {
	p, err := netip.ParsePrefix(value)
	if err != nil {
		return fmt.Errorf("%s invalid %q: %w", field, value, err)
	}
	if !p.Addr().Is4() {
		return fmt.Errorf("%s must be IPv4: %q", field, value)
	}
	return nil
}
