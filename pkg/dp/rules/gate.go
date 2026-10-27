// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 containd Authors

package rules

import "fmt"

// GateSelection is the compiled scan selection: which new TCP connections the
// engine steers through the scanning gate. Zones are resolved to kernel
// device names and addresses to canonical CIDRs, so the data plane never
// consults the control-plane configuration. It is immutable once compiled.
//
// Include entries select; exclude entries win over every include. Within an
// entry every populated field must match; an empty SourceDevices or
// DestZones means any. A connection matches on its effective (post-DNAT)
// destination.
type GateSelection struct {
	// Enabled is false when nothing is to be steered: Include and Exclude
	// are then empty, whatever the configuration holds.
	Enabled bool
	Include []GateEntry
	Exclude []GateEntry
	// Zones indexes every egress zone an include entry references. The
	// compiler writes Index into the connection mark, so an index is 1..255
	// and unique within the snapshot.
	Zones []GateZone
	// ICSDevices are the kernel devices of ICS-marked zones; ICSCIDRs are the
	// configured subnets of those zones' interfaces plus the addresses of
	// ICS-marked assets. A connection with either endpoint on them passes
	// unscanned outcomes under a closed fail policy.
	ICSDevices []string
	ICSCIDRs   []string
	// FailPolicy is open or closed; DownloadMode is hold or stream_tail.
	FailPolicy   string
	DownloadMode string
}

// GateZone binds an egress zone referenced by the selection to its devices
// and its connection-mark index.
type GateZone struct {
	Name    string
	Index   uint8
	Devices []string
}

// GateEntry is one resolved include or exclude entry. An include entry names
// its egress zones in DestZones, each present in GateSelection.Zones with
// its index and devices; an exclude entry carries its egress devices in
// DestDevices instead and sets no index.
//
// Family is 0 when the entry has no address constraint and applies to both
// IP families; otherwise it is 4 or 6 and Sources/Destinations hold only
// prefixes of that family. A configured entry whose address constraints
// cover one family compiles to that family alone, never to an unconstrained
// entry for the other.
type GateEntry struct {
	SourceDevices []string // ingress devices; empty = any
	DestZones     []string // include entries: names in Zones, never empty
	DestDevices   []string // exclude entries: egress devices; empty = any
	Family        uint8
	Sources       []string        // CIDRs; exclude entries only
	Destinations  []string        // CIDRs; exclude entries only
	Ports         []GatePortRange // empty = any port (exclude entries only)
}

// GatePortRange is a closed destination port range.
type GatePortRange struct {
	Lo uint16
	Hi uint16
}

// Validate guards a snapshot received without control-plane compilation: no
// include entry may cover an ICS decoder port and the zone indices must fit
// the connection mark. It runs before enforcement or the snapshot swap.
func (g GateSelection) Validate() error {
	for i, entry := range g.Include {
		for _, r := range entry.Ports {
			if r.Lo > r.Hi {
				return fmt.Errorf("gate include[%d]: reversed port range %d-%d", i, r.Lo, r.Hi)
			}
			if p, ok := ICSDecoderPortIn(r.Lo, r.Hi); ok {
				return fmt.Errorf("gate include[%d]: ports %d-%d cover ICS decoder port %s; scan selection may not include an ICS decoder port", i, r.Lo, r.Hi, p)
			}
		}
	}
	seen := make(map[uint8]string, len(g.Zones))
	for _, z := range g.Zones {
		if z.Index == 0 {
			return fmt.Errorf("gate zone %q has index 0; indices are 1-255", z.Name)
		}
		if other, dup := seen[z.Index]; dup {
			return fmt.Errorf("gate zones %q and %q share index %d", other, z.Name, z.Index)
		}
		seen[z.Index] = z.Name
	}
	return nil
}
