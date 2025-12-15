package engineapp

import (
	"net"
	"sort"
	"strings"

	"github.com/containd/containd/pkg/cp/config"
)

// resolveRoutingIfaces maps route Iface fields that refer to logical interface names
// (e.g. "wan", "lan1") into kernel device names using Interface.Device bindings.
//
// This keeps the control-plane model stable while allowing the dataplane to apply
// routes against the kernel's interface namespace.
func resolveRoutingIfaces(routing config.RoutingConfig, ifaces []config.Interface) config.RoutingConfig {
	if len(routing.Routes) == 0 {
		return routing
	}
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

	out := routing
	out.Routes = append([]config.StaticRoute(nil), routing.Routes...)

	for i := range out.Routes {
		name := strings.TrimSpace(out.Routes[i].Iface)
		if name == "" {
			continue
		}
		// If the route already points to a real kernel interface, keep it.
		if _, err := net.InterfaceByName(name); err == nil {
			continue
		}
		if dev, ok := byLogical[name]; ok && strings.TrimSpace(dev) != "" {
			out.Routes[i].Iface = dev
		}
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
