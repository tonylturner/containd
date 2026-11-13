// SPDX-License-Identifier: Apache-2.0

package inventory

import "github.com/tonylturner/containd/pkg/dp/limits"

// LimitOccupancy counts all retained IEC points without expiring or refreshing
// them. Bytes are not charged for this table.
func (inv *Inventory) LimitOccupancy() limits.Occupancy {
	s := &inv.iec104
	s.mu.Lock()
	defer s.mu.Unlock()
	limit := s.pointLimit
	if limit <= 0 {
		limit = limits.MaxInventoryPoints
	}
	return limits.Occupancy{
		Limit:     int64(limit),
		Entries:   int64(len(s.pointEntries)),
		HighWater: s.pointHighWater,
	}
}
