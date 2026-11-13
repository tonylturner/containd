// SPDX-License-Identifier: Apache-2.0

package inventory

import (
	"net/netip"
	"testing"
	"time"
)

func TestInventoryLimitOccupancy(t *testing.T) {
	inv := New()
	inv.ObserveIEC104(IEC104Observation{Controlling: netip.MustParseAddrPort("192.0.2.1:4000"), Controlled: netip.MustParseAddrPort("192.0.2.2:2404"), CA: 1, TypeID: 1, IOAs: []uint32{1, 2}, Time: time.Now()})
	if o := inv.LimitOccupancy(); o.Limit != 128*32*256 || o.Entries != 2 || o.ChargedBytes != 0 {
		t.Fatalf("occupancy %+v", o)
	}
}
