// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

package engineapp

import (
	"sort"
	"strings"

	"github.com/tonylturner/containd/pkg/cp/config"
)

// resolveRoutingIfaces copies and normalizes row-name references. A route
// without an Iface uses its named gateway's row name in the dataplane.
func resolveRoutingIfaces(routing config.RoutingConfig) config.RoutingConfig {
	out := routing
	out.Gateways = append([]config.Gateway(nil), routing.Gateways...)
	for i := range out.Gateways {
		out.Gateways[i].Iface = strings.TrimSpace(out.Gateways[i].Iface)
	}
	out.Routes = append([]config.StaticRoute(nil), routing.Routes...)
	for i := range out.Routes {
		out.Routes[i].Iface = strings.TrimSpace(out.Routes[i].Iface)
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
