// SPDX-License-Identifier: Apache-2.0

package engine

import (
	"net"
	"slices"
	"strings"

	"github.com/tonylturner/containd/pkg/common/protection"
	"github.com/tonylturner/containd/pkg/dp/rules"
)

// ReconcileInterfaceAttachment observes attachment, not link readiness or
// delivery. The ownership reconciler supplies its current admitted identity.
// No owner acknowledgement or installed policy is changed by this observation.
func (e *Engine) ReconcileInterfaceAttachment(m protection.Metadata) {
	e.reconcileInterfaceAttachment(m, attachedDevices)
}

func attachedDevices() ([]string, error) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, err
	}
	names := make([]string, 0, len(ifaces))
	for _, iface := range ifaces {
		names = append(names, iface.Name)
	}
	return names, nil
}

func (e *Engine) reconcileInterfaceAttachment(m protection.Metadata, discover func() ([]string, error)) {
	// Keep the observed snapshot installed until publication. The metadata
	// check also excludes a superseded attempt while discovery was in flight.
	e.lifecycleMu.Lock()
	defer e.lifecycleMu.Unlock()
	p := e.protection
	p.mu.Lock()
	current := p.status.metadata() == m && p.status.Installed != nil
	p.mu.Unlock()
	if !current {
		return
	}
	snap := e.ruleSnap.Load()
	devices, err := discover()
	p.update(func() {
		if p.status.metadata() != m {
			return
		}
		if err != nil {
			p.setLocked("interface-attachment", "unknown", "interface discovery failed: "+err.Error(), 0, 0)
			return
		}
		reason := missingZoneAttachments(snap, devices)
		state := "ready"
		if reason != "" {
			state = "degraded"
		}
		p.setLocked("interface-attachment", state, reason, 0, 0)
	})
}

func missingZoneAttachments(snap *rules.Snapshot, devices []string) string {
	if snap == nil {
		return ""
	}
	referenced := map[string]bool{}
	add := func(zones ...string) {
		for _, zone := range zones {
			if zone != "" {
				referenced[zone] = true
			}
		}
	}
	for _, entry := range snap.Firewall {
		add(entry.SourceZones...)
		add(entry.DestZones...)
	}
	if snap.NAT.Enabled {
		add(snap.NAT.EgressZone)
		add(snap.NAT.SourceZones...)
	}
	// Publishing is independent of the source-NAT enable switch.
	for _, forward := range snap.NAT.PortForwards {
		if forward.Enabled {
			add(forward.IngressZone)
		}
	}
	for _, rule := range snap.LocalInput {
		// Compiled VPN listeners already carry their implicit WAN zone.
		// Explicit interface selectors are not zone predicates.
		if len(rule.Ifaces) == 0 {
			add(rule.Zone)
		}
	}
	live := make(map[string]bool, len(devices))
	for _, device := range devices {
		live[device] = true
	}
	var zones []string
	for zone := range referenced {
		rows := snap.ZoneIfaces[zone]
		if len(rows) == 0 {
			continue
		}
		attached := false
		for _, row := range rows {
			attached = attached || live[row]
		}
		if !attached {
			zones = append(zones, zone)
		}
	}
	slices.Sort(zones)
	clauses := make([]string, 0, len(zones))
	for _, zone := range zones {
		rows := slices.Clone(snap.ZoneIfaces[zone])
		slices.Sort(rows)
		rows = slices.Compact(rows)
		clauses = append(clauses, "zone "+zone+" has no attached interface: "+strings.Join(rows, ", "))
	}
	return strings.Join(clauses, "; ")
}
