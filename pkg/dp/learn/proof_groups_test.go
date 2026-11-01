// SPDX-License-Identifier: Apache-2.0
package learn

import (
	"fmt"
	"testing"

	"github.com/tonylturner/containd/pkg/evidence"
)

func TestProofFragmentsKeepClosedDomainWitnesses(t *testing.T) {
	fc := uint8(5)
	group := &relationGroup{}
	for i := range 2 * maxProofParents {
		value := uint16(0)
		if i >= maxProofParents {
			value = 0xff00
		}
		group.parents = append(group.parents, evidence.Observation{ID: fmt.Sprint(i), Modbus: &evidence.Modbus{FunctionCode: &fc, Values: []uint16{value}}})
	}
	parts, ok := boundedProofGroups(group)
	if !ok || len(parts) < 2 {
		t.Fatal("large closed relation lost", ok)
	}
	covered := map[string]bool{}
	for _, part := range parts {
		if len(part.parents) > maxProofParents || len(closedDomains(part.parents)) != 0 {
			t.Fatal("proof fragment lost closed-domain coverage")
		}
		seen := map[string]bool{}
		for _, p := range part.parents {
			if seen[p.ID] {
				t.Fatal("duplicate positive inside one proof")
			}
			seen[p.ID] = true
			covered[p.ID] = true
		}
	}
	if len(covered) != len(group.parents) {
		t.Fatal("proof fragmentation sampled positive evidence")
	}
}
