// SPDX-License-Identifier: Apache-2.0

package anomaly

import (
	"testing"
	"time"

	"github.com/tonylturner/containd/pkg/dp/limits"
)

func TestRateLimitOccupancy(t *testing.T) {
	d := New()
	d.writeRate.recordAt("write", time.Now())
	d.totalRate.recordAt("total", time.Now())
	d.updateRateHighWater()
	if o := d.LimitOccupancy(); o.Limit != 2*limits.MaxRateTrackers || o.Entries != 2 || o.HighWater != 2 || o.ChargedBytes != 0 {
		t.Fatalf("occupancy %+v", o)
	}
}
