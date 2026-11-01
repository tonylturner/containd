// SPDX-License-Identifier: Apache-2.0
package learn

import "github.com/tonylturner/containd/pkg/evidence"

// boundedProofGroups preserves aggregate closed-domain witnesses when splitting
// large relations. No fragment may forget values required to justify its rule.
// Every original parent remains a positive input in at least one fragment.
func boundedProofGroups(group *relationGroup) ([]*relationGroup, bool) {
	if len(group.parents) <= maxProofParents {
		return []*relationGroup{group}, true
	}
	individual := true
	for _, p := range group.parents {
		if len(closedDomains([]evidence.Observation{p})) > 0 {
			individual = false
			break
		}
	}
	var basis []evidence.Observation
	witnesses := map[string]bool{}
	if !individual {
		facts := map[string]bool{}
		for _, p := range group.parents {
			key, err := evidence.Digest(struct {
				Modbus      *evidence.Modbus
				DNP3        *evidence.DNP3
				IEC104      *evidence.IEC104
				Coordinates evidence.Coordinates
			}{p.Modbus, p.DNP3, p.IEC104, p.Service.Coordinates})
			if err != nil {
				return nil, false
			}
			if facts[key] {
				continue
			}
			facts[key] = true
			basis = append(basis, p)
			witnesses[p.ID] = true
		}
		if len(basis) >= maxProofParents {
			return nil, false
		}
	}
	var parts []*relationGroup
	current := &relationGroup{rules: group.rules, parents: append([]evidence.Observation{}, basis...)}
	for _, p := range group.parents {
		if witnesses[p.ID] {
			continue
		}
		if len(current.parents) == maxProofParents {
			parts = append(parts, current)
			current = &relationGroup{rules: group.rules, parents: append([]evidence.Observation{}, basis...)}
		}
		current.parents = append(current.parents, p)
	}
	if len(current.parents) > 0 {
		parts = append(parts, current)
	}
	return parts, true
}
