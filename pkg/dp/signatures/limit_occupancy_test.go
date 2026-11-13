// SPDX-License-Identifier: Apache-2.0

package signatures

import "testing"

func TestSignatureLimitOccupancy(t *testing.T) {
	e := New()
	e.thresholds = map[thresholdKey]*thresholdState{{sigID: "one"}: {}}
	e.thresholdHighWater = 1
	if o := e.LimitOccupancy(); o.Limit != 4096 || o.Entries != 1 || o.HighWater != 1 || o.ChargedBytes != 0 {
		t.Fatalf("occupancy %+v", o)
	}
}
