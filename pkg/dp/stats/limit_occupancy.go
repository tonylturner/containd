// SPDX-License-Identifier: Apache-2.0

package stats

import "github.com/tonylturner/containd/pkg/dp/limits"

// LimitOccupancy reports retained top-talker rows; memory charging is not
// instrumented for this table.
func (t *Tracker) LimitOccupancy() limits.Occupancy {
	if t == nil {
		return limits.Occupancy{}
	}
	t.mu.RLock()
	defer t.mu.RUnlock()
	return limits.Occupancy{Limit: int64(t.topTalkerLimit()), Entries: int64(len(t.flows)), HighWater: t.highWater}
}
