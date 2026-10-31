// SPDX-License-Identifier: Apache-2.0
package rules

import (
	"fmt"
	"slices"
)

// WithStableZoneIndices compiles a detached zone allocation, retaining indices
// for surviving names. Engine publication uses the same allocator on snapshots
// received from management; no control-plane config is needed. Retired indices
// remain reserved for this allocation. Before subsequent reuse, the engine must
// successfully masked-clear retired indices from gated conntrack entries.
func (g GateSelection) WithStableZoneIndices(previous []GateZone) (GateSelection, error) {
	used := map[uint8]bool{}
	byName := map[string]uint8{}
	for _, zone := range previous {
		if zone.Index == 0 || used[zone.Index] || zone.Name == "" || byName[zone.Name] != 0 {
			return GateSelection{}, fmt.Errorf("invalid previous gate zone allocation: %s/%d", zone.Name, zone.Index)
		}
		used[zone.Index] = true
		byName[zone.Name] = zone.Index
	}
	g.Zones = slices.Clone(g.Zones)
	names := map[string]bool{}
	for i := range g.Zones {
		zone := &g.Zones[i]
		if zone.Name == "" || names[zone.Name] {
			return GateSelection{}, fmt.Errorf("invalid or duplicate gate zone name %q", zone.Name)
		}
		names[zone.Name] = true
		zone.Devices = slices.Clone(zone.Devices)
		if index := byName[zone.Name]; index != 0 {
			zone.Index = index
			continue
		}
		index := 1
		for index <= 255 && used[uint8(index)] {
			index++
		}
		if index > 255 {
			return GateSelection{}, fmt.Errorf("gate zone indices exhausted; clear retired conntrack indices before reuse")
		}
		zone.Index = uint8(index)
		used[uint8(index)] = true
	}
	return g, nil
}
