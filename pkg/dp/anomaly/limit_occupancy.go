// SPDX-License-Identifier: Apache-2.0

package anomaly

import "github.com/tonylturner/containd/pkg/dp/limits"

// LimitOccupancy counts host-pair keys in both independent rate trackers.
func (d *Detector) LimitOccupancy() limits.Occupancy {
	d.mu.Lock()
	defer d.mu.Unlock()
	return limits.Occupancy{
		Limit:     2 * limits.MaxRateTrackers,
		Entries:   int64(len(d.writeRate.buckets) + len(d.totalRate.buckets)),
		HighWater: d.rateHighWater,
	}
}
