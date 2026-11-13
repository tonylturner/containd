// SPDX-License-Identifier: Apache-2.0

package stats

import "github.com/tonylturner/containd/pkg/dp/limits"

// LimitOccupancy reports retained rows; the tracker has no retention cap yet.
func (t *Tracker) LimitOccupancy() limits.Occupancy {
	if t == nil {
		return limits.Occupancy{}
	}
	t.mu.RLock()
	defer t.mu.RUnlock()
	return limits.Occupancy{Entries: int64(len(t.flows))}
}
