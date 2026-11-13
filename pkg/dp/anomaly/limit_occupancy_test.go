// SPDX-License-Identifier: Apache-2.0

package anomaly

import "testing"

func TestRateLimitOccupancy(t *testing.T) {
	d := New()
	d.writeRate.buckets["write"] = map[int64]int{1: 1}
	d.totalRate.buckets["total"] = map[int64]int{1: 1}
	if o := d.LimitOccupancy(); o.Limit != 0 || o.Entries != 2 || o.ChargedBytes != 0 {
		t.Fatalf("occupancy %+v", o)
	}
}
