// SPDX-License-Identifier: Apache-2.0

package inventory

import (
	"net/netip"
	"testing"
	"time"

	"github.com/tonylturner/containd/pkg/dp/limits"
)

func TestInventoryLimitOccupancy(t *testing.T) {
	inv := New()
	inv.ObserveIEC104(IEC104Observation{Controlling: netip.MustParseAddrPort("192.0.2.1:4000"), Controlled: netip.MustParseAddrPort("192.0.2.2:2404"), CA: 1, TypeID: 1, IOAs: []uint32{1, 2}, Time: time.Now()})
	if o := inv.LimitOccupancy(); o.Limit != limits.MaxInventoryPoints || o.Entries != 2 || o.HighWater != 2 || o.ChargedBytes != 0 {
		t.Fatalf("occupancy %+v", o)
	}
}

func TestGlobalIECPointLRUAndEvictionAccounting(t *testing.T) {
	inv := New()
	ledger := limits.NewLedger(nil)
	inv.SetLimits(limits.Default(), limits.NewBudget(1), ledger)
	inv.iec104.mu.Lock()
	inv.iec104.pointLimit = 3
	inv.iec104.mu.Unlock()
	o := IEC104Observation{
		Controlling: netip.MustParseAddrPort("192.0.2.1:4000"),
		Controlled:  netip.MustParseAddrPort("192.0.2.2:2404"),
		CA:          1,
		TypeID:      1,
		Time:        time.Now(),
	}
	for i := uint32(1); i <= 40; i++ {
		o.IOAs = []uint32{i}
		inv.ObserveIEC104(o)
	}
	o.IOAs = []uint32{40}
	inv.ObserveIEC104(o)
	o.IOAs = []uint32{41}
	inv.ObserveIEC104(o)
	points := inv.SnapshotIEC104().Pairs[0].CAs[0].Points
	if len(points) != 3 || points[0].IOA != 39 || points[1].IOA != 40 || points[2].IOA != 41 {
		t.Fatalf("globally retained points %+v", points)
	}
	occupancy := inv.LimitOccupancy()
	if occupancy.Limit != 3 || occupancy.Entries != 3 || occupancy.HighWater != 3 {
		t.Fatalf("global point occupancy %+v", occupancy)
	}
	overflow := inv.SnapshotIEC104().Overflow
	if overflow.Points != 38 {
		t.Fatalf("point overflow = %d, want 38", overflow.Points)
	}
	hits := ledger.Status(limits.TableInventoryPoints, limits.Occupancy{}).Hits
	if len(hits) != 1 || hits[0].Reason != limits.ReasonEvicted || hits[0].Mode != limits.ModeObserve || hits[0].Total != 38 {
		t.Fatalf("point ledger hits %+v", hits)
	}
}
