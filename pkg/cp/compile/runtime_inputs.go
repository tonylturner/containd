// SPDX-License-Identifier: Apache-2.0
package compile

import (
	"fmt"
	"net/netip"
	"slices"

	"github.com/tonylturner/containd/pkg/dp/markabi"
	"github.com/tonylturner/containd/pkg/dp/rules"
)

// SnapshotInputs is runtime evidence, never persisted operator configuration.
// Pass the last published Gate.Zones to retain surviving zone indices across
// configuration/selection reordering. Retired indices are not reused in this
// compile; the engine must close affected gate sessions before any later reuse.
type SnapshotInputs struct {
	AdmissionParity   uint32
	LocalIPv4ByDevice map[string][]netip.Addr
	PreviousGateZones []rules.GateZone
}

func (in SnapshotInputs) validate() error {
	if !markabi.ValidParity(in.AdmissionParity) {
		return fmt.Errorf("admission parity must be zero or %#x", markabi.ParityBit)
	}
	for dev, addresses := range in.LocalIPv4ByDevice {
		if dev == "" {
			return fmt.Errorf("local IPv4 device cannot be empty")
		}
		for _, address := range addresses {
			if !address.Is4() {
				return fmt.Errorf("local address on %s must be IPv4: %s", dev, address)
			}
		}
	}
	return nil
}

func copyLocalIPv4(in map[string][]netip.Addr) map[string][]netip.Addr {
	if in == nil {
		return nil
	}
	out := make(map[string][]netip.Addr, len(in))
	for dev, addresses := range in {
		copy := slices.Clone(addresses)
		slices.SortFunc(copy, netip.Addr.Compare)
		out[dev] = slices.Compact(copy)
	}
	return out
}
