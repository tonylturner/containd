// SPDX-License-Identifier: Apache-2.0

package inventory

import "github.com/tonylturner/containd/pkg/dp/limits"

// LimitOccupancy counts all retained IEC points without expiring or refreshing
// them. The existing hierarchical bound is not yet the smaller global cap.
func (inv *Inventory) LimitOccupancy() limits.Occupancy {
	s := &inv.iec104
	s.mu.Lock()
	defer s.mu.Unlock()
	var n int64
	for _, p := range s.pairs.items {
		for _, ca := range p.Value.(*entry[pairKey, *pairState]).value.cas.items {
			n += int64(len(ca.Value.(*entry[uint16, *caState]).value.points.items))
		}
	}
	return limits.Occupancy{Limit: MaxIEC104Pairs * MaxIEC104CAs * MaxIEC104Points, Entries: n}
}
