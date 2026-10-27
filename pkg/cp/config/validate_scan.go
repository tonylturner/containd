// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 containd Authors

package config

import (
	"errors"
	"fmt"
	"net/netip"
	"sort"
	"strings"

	"github.com/tonylturner/containd/pkg/dp/rules"
)

// maxScanEgressZones is the number of egress zones a selection may reference:
// the engine stores the egress zone index in eight bits of the connection
// mark, and zero means no zone.
const maxScanEgressZones = 255

// ValidateScanSelection checks services.av.scan against the zones, assets,
// interfaces and dataplane settings it references. An error rejects the
// configuration; the returned warnings describe a selection that commits but
// intercepts or exempts less than it reads, for the commit response.
// Config.Validate and the snapshot compiler share it, so a snapshot can never
// carry an ICS decoder port.
func ValidateScanSelection(c *Config) ([]string, error) {
	if c == nil {
		return nil, errors.New("config is nil")
	}
	v := scanValidator{
		zones:   interfaceZoneSet(c.Zones),
		devices: ZoneDevices(c.Interfaces),
		warned:  map[string]struct{}{},
	}
	scan := c.Services.AV.Scan
	switch scan.EffectiveDownloadMode() {
	case ScanDownloadHold, ScanDownloadStreamTail:
	default:
		return nil, fmt.Errorf("services.av.scan.downloadMode must be %s or %s", ScanDownloadHold, ScanDownloadStreamTail)
	}
	if len(scan.Include) > 0 && !c.DataPlane.Enforcement {
		return nil, errors.New("services.av.scan.include needs dataplane.enforcement: the scanning gate steers connections with nftables")
	}
	egress := map[string]struct{}{}
	for i, entry := range scan.Include {
		if err := v.include(fmt.Sprintf("services.av.scan.include[%d]", i), entry, egress); err != nil {
			return nil, err
		}
	}
	if len(egress) > maxScanEgressZones {
		return nil, fmt.Errorf("services.av.scan.include references %d egress zones; at most %d zones can be selected", len(egress), maxScanEgressZones)
	}
	for i, entry := range scan.Exclude {
		if err := v.exclude(fmt.Sprintf("services.av.scan.exclude[%d]", i), entry); err != nil {
			return nil, err
		}
	}
	if err := v.zoneList("services.av.scan.icsZones", scan.ICSZones); err != nil {
		return nil, err
	}
	if err := v.icsAssets(c.Assets, scan.ICSAssets); err != nil {
		return nil, err
	}
	if len(scan.Include) > 0 && c.Services.AV.EffectiveFailPolicy() == "closed" && len(scan.ICSZones) == 0 && len(scan.ICSAssets) == 0 {
		v.warnings = append(v.warnings, "services.av.scan: failPolicy is closed with no icsZones or icsAssets; no endpoint passes unscanned content while the scanner is unavailable")
	}
	return v.warnings, nil
}

type scanValidator struct {
	zones    map[string]struct{}
	devices  map[string][]string
	warned   map[string]struct{}
	warnings []string
}

func (v *scanValidator) include(path string, entry ScanInclude, egress map[string]struct{}) error {
	if err := v.zoneList(path+".sourceZones", entry.SourceZones); err != nil {
		return err
	}
	if err := v.zoneList(path+".destZones", entry.DestZones); err != nil {
		return err
	}
	if len(entry.DestPorts) == 0 {
		return fmt.Errorf("%s.destPorts must list at least one port", path)
	}
	for _, spec := range entry.DestPorts {
		lo, hi, err := ScanPortRange(spec)
		if err != nil {
			return fmt.Errorf("%s.destPorts: %w", path, err)
		}
		if p, ok := rules.ICSDecoderPortIn(lo, hi); ok {
			return fmt.Errorf("%s.destPorts %q covers ICS decoder port %s; scan selection may not include an ICS decoder port", path, spec, p)
		}
	}
	if len(entry.DestZones) == 0 {
		for z := range v.zones {
			egress[z] = struct{}{}
		}
	}
	for _, z := range entry.DestZones {
		egress[z] = struct{}{}
	}
	return nil
}

func (v *scanValidator) exclude(path string, entry ScanExclude) error {
	if len(entry.SourceZones)+len(entry.DestZones)+len(entry.Sources)+len(entry.Destinations)+len(entry.DestPorts) == 0 {
		return fmt.Errorf("%s must set at least one of sourceZones, destZones, sources, destinations or destPorts", path)
	}
	if err := v.zoneList(path+".sourceZones", entry.SourceZones); err != nil {
		return err
	}
	if err := v.zoneList(path+".destZones", entry.DestZones); err != nil {
		return err
	}
	if err := scanCIDRs(path+".sources", entry.Sources); err != nil {
		return err
	}
	if err := scanCIDRs(path+".destinations", entry.Destinations); err != nil {
		return err
	}
	for _, spec := range entry.DestPorts {
		if _, _, err := ScanPortRange(spec); err != nil {
			return fmt.Errorf("%s.destPorts: %w", path, err)
		}
	}
	return nil
}

func scanCIDRs(path string, cidrs []string) error {
	for _, raw := range cidrs {
		if _, err := ScanCIDR(raw); err != nil {
			return fmt.Errorf("%s: %w", path, err)
		}
	}
	return nil
}

// zoneList rejects unknown zones and warns once per zone that has no
// interface, since such a zone can match no traffic.
func (v *scanValidator) zoneList(path string, names []string) error {
	for _, name := range names {
		if _, ok := v.zones[name]; !ok {
			return fmt.Errorf("%s: unknown zone %q", path, name)
		}
		if _, warned := v.warned[name]; warned || len(v.devices[name]) > 0 {
			continue
		}
		v.warned[name] = struct{}{}
		v.warnings = append(v.warnings, fmt.Sprintf("%s: zone %q has no interface bound to it, so it selects no traffic", path, name))
	}
	return nil
}

func (v *scanValidator) icsAssets(assets []Asset, ids []string) error {
	byID := make(map[string]Asset, len(assets))
	for _, a := range assets {
		byID[a.ID] = a
	}
	for _, id := range ids {
		a, ok := byID[id]
		if !ok {
			return fmt.Errorf("services.av.scan.icsAssets: unknown asset %q", id)
		}
		if len(a.IPs) == 0 {
			v.warnings = append(v.warnings, fmt.Sprintf("services.av.scan.icsAssets: asset %q has no IP address, so it marks no endpoint", id))
		}
	}
	return nil
}

// ScanPortRange parses one destination port entry of the scan selection:
// a decimal port or an inclusive N-M range, both above zero. Validation and
// snapshot compilation share it.
func ScanPortRange(spec string) (lo, hi uint16, err error) {
	lo, hi, err = rules.ParsePortRange(strings.TrimSpace(spec))
	if err != nil {
		return 0, 0, err
	}
	if lo == 0 {
		return 0, 0, fmt.Errorf("port %q: ports start at 1", spec)
	}
	return lo, hi, nil
}

// ScanCIDR parses one address entry of the scan selection into its masked
// prefix. Validation and snapshot compilation share it.
func ScanCIDR(raw string) (netip.Prefix, error) {
	p, err := netip.ParsePrefix(strings.TrimSpace(raw))
	if err != nil || p.Addr().Zone() != "" {
		return netip.Prefix{}, fmt.Errorf("invalid CIDR %q", raw)
	}
	if p.Addr().Is4In6() {
		if p.Bits() < 96 {
			return netip.Prefix{}, fmt.Errorf("invalid CIDR %q: an IPv4-mapped prefix needs at least 96 bits", raw)
		}
		p = netip.PrefixFrom(p.Addr().Unmap(), p.Bits()-96)
	}
	return p.Masked(), nil
}

// ZoneDevices maps each zone to the kernel device names of its interfaces,
// sorted: the bound device, or the logical name of an unbound interface.
func ZoneDevices(ifaces []Interface) map[string][]string {
	out := map[string][]string{}
	for _, iface := range ifaces {
		if iface.Zone == "" {
			continue
		}
		name := iface.Name
		if strings.TrimSpace(iface.Device) != "" {
			name = iface.Device
		}
		out[iface.Zone] = append(out[iface.Zone], name)
	}
	for z, devs := range out {
		sort.Strings(devs)
		out[z] = devs
	}
	return out
}
