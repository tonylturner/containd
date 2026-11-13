// SPDX-License-Identifier: Apache-2.0

package signatures

import "github.com/tonylturner/containd/pkg/dp/limits"

func (e *Engine) LimitOccupancy() limits.Occupancy {
	e.matchesMu.Lock()
	defer e.matchesMu.Unlock()
	return limits.Occupancy{Limit: maxThresholdKeys, Entries: int64(len(e.thresholds))}
}
