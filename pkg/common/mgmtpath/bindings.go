// SPDX-License-Identifier: Apache-2.0
package mgmtpath

import (
	"net"
	"sort"
)

// Devices reads existing devices in the enforcement or management namespace.
// A deliberately down binding still exists and must not trigger recovery.
func Devices() ([]string, error) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, err
	}
	var names []string
	for _, iface := range ifaces {
		if iface.Flags&net.FlagLoopback == 0 {
			names = append(names, iface.Name)
		}
	}
	return names, nil
}

// ResolveBindings preserves configured allows whenever any binding exists. Otherwise
// an unbound appliance may expose the listener on discovered NICs, but never on
// an explicitly disabled binding. Call only when logical access was granted;
// all-access-off is a policy decision, not an unbound appliance.
func ResolveBindings(allowed, denied, live []string) (devices []string, recovery bool) {
	existing := make(map[string]bool, len(live))
	for _, name := range live {
		existing[name] = true
	}
	for _, name := range allowed {
		if existing[name] {
			devices = append(devices, name)
		}
	}
	if len(devices) > 0 {
		sort.Strings(devices)
		return devices, false
	}
	for _, name := range denied {
		delete(existing, name)
	}
	for name := range existing {
		devices = append(devices, name)
	}
	sort.Strings(devices)
	return devices, true
}
