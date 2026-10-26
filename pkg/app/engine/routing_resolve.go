// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

package engineapp

import (
	"net"
	"sort"
	"strings"

	"github.com/tonylturner/containd/pkg/cp/config"
)

func logicalInterfaceDeviceMap(ifaces []config.Interface) map[string]string {
	byLogical := map[string]string{}
	for _, iface := range ifaces {
		logical := strings.TrimSpace(iface.Name)
		if logical == "" {
			continue
		}
		dev := strings.TrimSpace(iface.Device)
		if dev == "" {
			dev = logical
		}
		byLogical[logical] = dev
	}
	return byLogical
}

func resolveInterfaceRef(ref string, byLogical map[string]string) string {
	name := strings.TrimSpace(ref)
	if name == "" {
		return ""
	}
	// If the value already names a real kernel interface, keep it.
	if _, err := net.InterfaceByName(name); err == nil {
		return name
	}
	if dev, ok := byLogical[name]; ok && strings.TrimSpace(dev) != "" {
		return dev
	}
	return name
}

// resolveRoutingIfaces maps the Iface fields of gateways and routes that refer to
// logical interface names (e.g. "wan", "lan1") into kernel device names using
// Interface.Device bindings. A route without an Iface uses its named gateway's
// Iface in the dataplane, so both must name kernel devices.
//
// This keeps the control-plane model stable while allowing the dataplane to apply
// routes against the kernel's interface namespace.
func resolveRoutingIfaces(routing config.RoutingConfig, ifaces []config.Interface) config.RoutingConfig {
	byLogical := logicalInterfaceDeviceMap(ifaces)

	out := routing
	out.Gateways = append([]config.Gateway(nil), routing.Gateways...)
	for i := range out.Gateways {
		out.Gateways[i].Iface = resolveInterfaceRef(out.Gateways[i].Iface, byLogical)
	}
	out.Routes = append([]config.StaticRoute(nil), routing.Routes...)
	for i := range out.Routes {
		out.Routes[i].Iface = resolveInterfaceRef(out.Routes[i].Iface, byLogical)
	}

	// Keep ordering stable for deterministic diffs in tests/logs when applied repeatedly.
	sort.SliceStable(out.Routes, func(i, j int) bool {
		li, lj := strings.TrimSpace(out.Routes[i].Dst), strings.TrimSpace(out.Routes[j].Dst)
		if li != lj {
			return li < lj
		}
		return strings.TrimSpace(out.Routes[i].Iface) < strings.TrimSpace(out.Routes[j].Iface)
	})

	return out
}

func resolveInterfaceRefs(refs []string, ifaces []config.Interface) []string {
	if len(refs) == 0 {
		return nil
	}
	byLogical := logicalInterfaceDeviceMap(ifaces)
	out := make([]string, 0, len(refs))
	for _, ref := range refs {
		if name := resolveInterfaceRef(ref, byLogical); name != "" {
			out = append(out, name)
		}
	}
	return out
}
