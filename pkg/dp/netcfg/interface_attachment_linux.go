// SPDX-License-Identifier: Apache-2.0
//go:build linux

package netcfg

import (
	"fmt"
	"net"
	"strings"

	"github.com/tonylturner/containd/pkg/cp/config"
)

// Prepare dependencies before their consumers, regardless of configuration
// order. An absent physical device defers its dependants, even if an old
// virtual device with their name still exists.
func prepareVirtualInterfaces(ifaces []config.Interface, resolver interfaceResolver) (map[string]string, map[string]bool, error) {
	live, err := net.Interfaces()
	if err != nil {
		return nil, nil, fmt.Errorf("discover interface attachment: %w", err)
	}
	exists := make(map[string]bool, len(live))
	for _, nic := range live {
		exists[nic.Name] = true
	}
	bridgeMembers := map[string]string{}
	// Membership is configuration intent even while a bridge is deferred.
	// Never run standalone addressing or DHCP on a live member just because
	// another member has not attached yet.
	for _, iface := range ifaces {
		if strings.EqualFold(strings.TrimSpace(iface.Type), "bridge") {
			for _, member := range iface.Members {
				bridgeMembers[resolver.resolveDev(member)] = resolver.deviceFor(iface)
			}
		}
	}
	unattached := map[string]bool{}
	prepared, visiting := map[string]bool{}, map[string]bool{}
	var prepare func(config.Interface) error
	prepare = func(iface config.Interface) error {
		dev := resolver.deviceFor(iface)
		if dev == "" || prepared[dev] {
			return nil
		}
		if visiting[dev] {
			return fmt.Errorf("interface dependency cycle at %s", dev)
		}
		visiting[dev] = true
		kind := strings.ToLower(strings.TrimSpace(iface.Type))
		var dependencies []string
		switch kind {
		case "vlan":
			dependencies = []string{iface.Parent}
		case "bridge":
			dependencies = iface.Members
		}
		for _, ref := range dependencies {
			dependency, ok := resolver.byName[strings.TrimSpace(ref)]
			if !ok {
				return fmt.Errorf("interface %s dependency %q is not a row", dev, ref)
			}
			if err := prepare(dependency); err != nil {
				return err
			}
			if unattached[resolver.deviceFor(dependency)] {
				unattached[dev] = true
			}
		}
		if !unattached[dev] {
			switch kind {
			case "bridge":
				err = ensureBridgeInterface(dev, iface, resolver)
			case "vlan":
				err = ensureVLANInterface(dev, iface, resolver)
			default:
				unattached[dev] = !exists[dev]
			}
			if err != nil {
				return err
			}
		}
		visiting[dev] = false
		prepared[dev] = true
		return nil
	}
	for _, iface := range ifaces {
		if err := prepare(iface); err != nil {
			return nil, nil, err
		}
	}
	return bridgeMembers, unattached, nil
}
