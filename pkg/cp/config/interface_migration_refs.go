// SPDX-License-Identifier: Apache-2.0
package config

import "strings"

// Legacy consumers did not share one resolution order. These maps describe the
// saved topology, without consulting the upgrading host's kernel interfaces.
type legacyInterfaceReferences struct {
	rows             map[string]bool
	devices          map[string]string
	duplicateDevices map[string]bool
	vpnDevices       map[string]string
}

func newLegacyInterfaceReferences(cfg *Config) legacyInterfaceReferences {
	r := legacyInterfaceReferences{
		rows:             map[string]bool{},
		devices:          map[string]string{},
		duplicateDevices: map[string]bool{},
		vpnDevices:       map[string]string{},
	}
	for i, row := range cfg.Interfaces {
		r.rows[row.Name] = true
		dev := ""
		if i < len(cfg.legacyDevices) {
			dev = strings.TrimSpace(cfg.legacyDevices[i])
		}
		if dev != "" {
			if previous, ok := r.devices[dev]; ok && previous != row.Name {
				r.duplicateDevices[dev] = true
			}
			r.devices[dev] = row.Name
		} else {
			dev = strings.TrimSpace(row.Name)
		}
		// The legacy VPN compiler inserted both keys for each row in saved
		// order. A later row could overwrite either a name or a device key.
		if name := strings.TrimSpace(row.Name); name != "" && dev != "" {
			r.vpnDevices[name] = dev
		}
		if dev != "" {
			r.vpnDevices[dev] = dev
		}
	}
	return r
}

func (r legacyInterfaceReferences) collision(ref string) bool {
	ref = strings.TrimSpace(ref)
	name, bound := r.devices[ref]
	return r.rows[ref] && bound && name != ref
}

func (r legacyInterfaceReferences) rowFirst(ref string) string {
	if r.rows[strings.TrimSpace(ref)] {
		return ref
	}
	return r.deviceFirst(ref)
}

// Routing checked existing kernel devices first; capture and forwarding used
// device names directly. Treat saved bindings as the existing kernel devices.
// Duplicate bindings remain unchanged because they do not identify one row.
func (r legacyInterfaceReferences) deviceFirst(ref string) string {
	key := strings.TrimSpace(ref)
	if name, ok := r.devices[key]; ok && !r.duplicateDevices[key] {
		return name
	}
	return ref
}

func (r legacyInterfaceReferences) vpnListener(ref string) string {
	if dev, ok := r.vpnDevices[strings.TrimSpace(ref)]; ok {
		return r.deviceFirst(dev)
	}
	return r.deviceFirst(ref)
}
