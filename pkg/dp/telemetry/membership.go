// SPDX-License-Identifier: Apache-2.0

// Package telemetry assembles cumulative engine counters without taking policy
// lifecycle locks. Kernel reads and process-owned counters remain separate sources.
package telemetry

import (
	"strings"

	"github.com/tonylturner/containd/pkg/cp/config"
)

// Interface is an immutable binding from the last successfully applied set.
type Interface struct{ Device, Zone, Role string }

// Membership distinguishes an applied empty set from interfaces not yet applied.
type Membership struct{ Interfaces []Interface }

// Bind resolves logical parent/member references before assigning leaf roles.
func Bind(ifaces []config.Interface) *Membership {
	devices := map[string]string{}
	for _, i := range ifaces {
		devices[i.Name] = device(i)
	}
	resolve := func(ref string) string {
		if d, ok := devices[ref]; ok {
			return d
		}
		return strings.TrimSpace(ref)
	}
	parents := map[string]bool{}
	for _, i := range ifaces {
		if strings.EqualFold(strings.TrimSpace(i.Type), "vlan") {
			parents[resolve(i.Parent)] = true
		}
		if strings.EqualFold(strings.TrimSpace(i.Type), "bridge") {
			for _, m := range i.Members {
				parents[resolve(m)] = true
			}
		}
	}
	m := &Membership{}
	for _, i := range ifaces {
		d := device(i)
		role := "leaf"
		if parents[d] {
			role = "parent"
		}
		m.Interfaces = append(m.Interfaces, Interface{d, i.Zone, role})
	}
	return m
}

func device(i config.Interface) string {
	return strings.TrimSpace(i.Name)
}

// Zones is the leaf-device accounting map. Parents and unzoned devices have
// no conduit membership.
func (m *Membership) Zones() map[string]string {
	zones := map[string]string{}
	if m != nil {
		for _, i := range m.Interfaces {
			if i.Zone != "" && i.Role == "leaf" {
				zones[i.Device] = i.Zone
			}
		}
	}
	return zones
}
