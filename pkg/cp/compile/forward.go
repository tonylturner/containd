// SPDX-License-Identifier: Apache-2.0
package compile

import (
	"net/netip"
	"slices"
	"strings"

	"github.com/tonylturner/containd/pkg/cp/config"
	"github.com/tonylturner/containd/pkg/dp/rules"
)

// ResolveForwardMatches resolves the enabled, bound forwards of an already
// validated candidate/running config. An absent result never means unrestricted.
// It is independent of NAT.Enabled, which controls source NAT, not publishing.
// Runtime device addresses are supplied separately in SnapshotInputs.
func ResolveForwardMatches(cfg *config.Config) map[string]rules.ForwardMatch {
	out := map[string]rules.ForwardMatch{}
	for _, forward := range cfg.Firewall.NAT.PortForwards {
		if !forward.Enabled {
			continue
		}
		var devices []string
		for _, iface := range cfg.Interfaces {
			if strings.TrimSpace(iface.Zone) != strings.TrimSpace(forward.IngressZone) {
				continue
			}
			device := strings.TrimSpace(iface.Device)
			kind := strings.ToLower(strings.TrimSpace(iface.Type))
			if device == "" && (kind == "bridge" || kind == "vlan") {
				device = iface.Name
			}
			if device != "" {
				devices = append(devices, device)
			}
		}
		if len(devices) == 0 {
			continue
		}
		slices.Sort(devices)
		backend, _ := netip.ParseAddr(strings.TrimSpace(forward.DestIP))
		port := forward.DestPort
		if port == 0 {
			port = forward.ListenPort
		}
		match := rules.ForwardMatch{Enabled: true, IngressDevices: slices.Compact(devices), Protocol: strings.ToLower(strings.TrimSpace(forward.Proto)),
			ListenPort: uint16(forward.ListenPort), Backend: netip.AddrPortFrom(backend, uint16(port))}
		if forward.ListenAddress != "" {
			match.ListenAddress, _ = netip.ParseAddr(forward.ListenAddress)
		}
		for _, source := range forward.AllowedSources {
			prefix, _ := netip.ParsePrefix(strings.TrimSpace(source))
			match.AllowedSources = append(match.AllowedSources, prefix.Masked())
		}
		slices.SortFunc(match.AllowedSources, func(a, b netip.Prefix) int {
			if c := a.Addr().Compare(b.Addr()); c != 0 {
				return c
			}
			return a.Bits() - b.Bits()
		})
		match.AllowedSources = slices.Compact(match.AllowedSources)
		out[forward.ID] = match
	}
	return out
}
