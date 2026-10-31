// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 containd Authors

package compile

import (
	"net/netip"
	"slices"
	"sort"

	"github.com/tonylturner/containd/pkg/cp/config"
	dprules "github.com/tonylturner/containd/pkg/dp/rules"
)

// compileGate resolves services.av.scan into the data-plane gate selection:
// zones to the devices in zoneIfaces, addresses to canonical CIDRs, ports to
// merged ranges. Output order follows the configuration, so equal
// configurations compile to equal selections. The configuration has been
// validated, so every parse below succeeds.
func compileGate(cfg *config.Config, zoneIfaces map[string][]string) dprules.GateSelection {
	av := cfg.Services.AV
	gate := dprules.GateSelection{
		Enabled:      av.ScanGateEnabled(),
		FailPolicy:   av.EffectiveFailPolicy(),
		DownloadMode: av.Scan.EffectiveDownloadMode(),
	}
	if !gate.Enabled {
		return gate
	}
	gate.Zones = gateZones(cfg, av.Scan.Include, zoneIfaces)
	for _, entry := range av.Scan.Include {
		sources, matchable := gateDevices(entry.SourceZones, zoneIfaces)
		if !matchable {
			continue
		}
		dest := gateEgressZones(cfg.Zones, entry.DestZones, zoneIfaces)
		if len(dest) == 0 {
			continue
		}
		gate.Include = append(gate.Include, dprules.GateEntry{
			SourceDevices: sources,
			DestZones:     dest,
			Ports:         gatePorts(entry.DestPorts),
		})
	}
	for _, entry := range av.Scan.Exclude {
		gate.Exclude = append(gate.Exclude, gateExcludeEntries(entry, zoneIfaces)...)
	}
	gate.ICSDevices, gate.ICSCIDRs = gateICSEndpoints(cfg, zoneIfaces)
	return gate
}

// gateZones lists every egress zone the include entries reference, in
// configuration order, whether or not it has a device yet: binding a device
// later must not retire its allocation. WithStableZoneIndices assigns indices.
// An entry without destZones
// references every zone.
func gateZones(cfg *config.Config, include []config.ScanInclude, zoneIfaces map[string][]string) []dprules.GateZone {
	referenced := map[string]struct{}{}
	for _, entry := range include {
		if len(entry.DestZones) == 0 {
			for _, z := range cfg.Zones {
				referenced[z.Name] = struct{}{}
			}
			break
		}
		for _, name := range entry.DestZones {
			referenced[name] = struct{}{}
		}
	}
	var zones []dprules.GateZone
	for _, z := range cfg.Zones {
		if _, ok := referenced[z.Name]; !ok {
			continue
		}
		zones = append(zones, dprules.GateZone{
			Name:    z.Name,
			Devices: slices.Clone(zoneIfaces[z.Name]),
		})
	}
	return zones
}

// gateEgressZones lists the egress zones of an include entry in
// configuration order, keeping only zones with a device; an empty names
// list means every zone.
func gateEgressZones(zones []config.Zone, names []string, zoneIfaces map[string][]string) []string {
	var out []string
	for _, z := range zones {
		if len(zoneIfaces[z.Name]) == 0 || (len(names) > 0 && !slices.Contains(names, z.Name)) {
			continue
		}
		out = append(out, z.Name)
	}
	return out
}

// gateDevices resolves zone names to a sorted device set. Empty names mean
// any device and report matchable; named zones without any device can match
// nothing and report false.
func gateDevices(names []string, zoneIfaces map[string][]string) (devices []string, matchable bool) {
	if len(names) == 0 {
		return nil, true
	}
	for _, name := range names {
		devices = append(devices, zoneIfaces[name]...)
	}
	if len(devices) == 0 {
		return nil, false
	}
	sort.Strings(devices)
	return slices.Compact(devices), true
}

// gatePorts parses, sorts and merges overlapping or adjacent port ranges.
func gatePorts(specs []string) []dprules.GatePortRange {
	ranges := make([]dprules.GatePortRange, 0, len(specs))
	for _, spec := range specs {
		lo, hi, _ := config.ScanPortRange(spec)
		ranges = append(ranges, dprules.GatePortRange{Lo: lo, Hi: hi})
	}
	sort.Slice(ranges, func(i, j int) bool {
		if ranges[i].Lo != ranges[j].Lo {
			return ranges[i].Lo < ranges[j].Lo
		}
		return ranges[i].Hi < ranges[j].Hi
	})
	merged := ranges[:0]
	for _, r := range ranges {
		if n := len(merged); n > 0 && int(r.Lo) <= int(merged[n-1].Hi)+1 {
			merged[n-1].Hi = max(merged[n-1].Hi, r.Hi)
			continue
		}
		merged = append(merged, r)
	}
	return merged
}

// gateExcludeEntries resolves one exclude entry. An entry without address
// constraints applies to both families; otherwise it compiles once per
// family that has prefixes on every constrained side, so a constraint on
// one family never becomes an unconstrained match on the other.
func gateExcludeEntries(entry config.ScanExclude, zoneIfaces map[string][]string) []dprules.GateEntry {
	sources, srcMatchable := gateDevices(entry.SourceZones, zoneIfaces)
	dest, dstMatchable := gateDevices(entry.DestZones, zoneIfaces)
	if !srcMatchable || !dstMatchable {
		return nil
	}
	base := dprules.GateEntry{SourceDevices: sources, DestDevices: dest}
	if len(entry.DestPorts) > 0 {
		base.Ports = gatePorts(entry.DestPorts)
	}
	if len(entry.Sources) == 0 && len(entry.Destinations) == 0 {
		return []dprules.GateEntry{base}
	}
	var out []dprules.GateEntry
	for _, family := range []uint8{4, 6} {
		srcs := gateCIDRs(entry.Sources, family)
		dsts := gateCIDRs(entry.Destinations, family)
		if (len(entry.Sources) > 0 && len(srcs) == 0) || (len(entry.Destinations) > 0 && len(dsts) == 0) {
			continue
		}
		e := base
		e.Family, e.Sources, e.Destinations = family, srcs, dsts
		out = append(out, e)
	}
	return out
}

// gateCIDRs returns the canonical prefixes of one family, sorted and
// deduplicated.
func gateCIDRs(raw []string, family uint8) []string {
	var prefixes []netip.Prefix
	for _, s := range raw {
		p, err := config.ScanCIDR(s)
		if err != nil || (family == 4) != p.Addr().Is4() {
			continue
		}
		prefixes = append(prefixes, p)
	}
	return sortedPrefixes(prefixes)
}

func sortedPrefixes(prefixes []netip.Prefix) []string {
	if len(prefixes) == 0 {
		return nil
	}
	slices.SortFunc(prefixes, func(a, b netip.Prefix) int {
		if c := a.Addr().Compare(b.Addr()); c != 0 {
			return c
		}
		return a.Bits() - b.Bits()
	})
	out := make([]string, 0, len(prefixes))
	for _, p := range slices.Compact(prefixes) {
		out = append(out, p.String())
	}
	return out
}

// gateICSEndpoints resolves icsZones to their devices and configured
// interface subnets, and icsAssets to host prefixes of their addresses.
func gateICSEndpoints(cfg *config.Config, zoneIfaces map[string][]string) (devices, cidrs []string) {
	scan := cfg.Services.AV.Scan
	devices, _ = gateDevices(scan.ICSZones, zoneIfaces)
	var prefixes []netip.Prefix
	for _, iface := range cfg.Interfaces {
		if !slices.Contains(scan.ICSZones, iface.Zone) {
			continue
		}
		for _, addr := range iface.Addresses {
			if p, err := config.ScanCIDR(addr); err == nil {
				prefixes = append(prefixes, p)
			}
		}
	}
	for _, asset := range cfg.Assets {
		if !slices.Contains(scan.ICSAssets, asset.ID) {
			continue
		}
		for _, ip := range asset.IPs {
			addr, ok := dprules.BindingAddr(ip)
			if !ok {
				continue
			}
			prefixes = append(prefixes, netip.PrefixFrom(addr, addr.BitLen()))
		}
	}
	return devices, sortedPrefixes(prefixes)
}
