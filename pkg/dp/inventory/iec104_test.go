// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 containd Authors

package inventory

import (
	"fmt"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/tonylturner/containd/pkg/dp/dpi"
)

func observation() IEC104Observation {
	return IEC104Observation{SessionID: "session", Controlling: netip.MustParseAddrPort("192.0.2.1:50000"), Controlled: netip.MustParseAddrPort("192.0.2.2:2404"), CA: 1, TypeID: 45, IOAs: []uint32{10}, ControlDirection: true, Time: time.Now().UTC()}
}

func TestIEC104CountsAndDetachedSnapshot(t *testing.T) {
	inv := New()
	o := observation()
	inv.ObserveIEC104(o)
	o.Time = o.Time.Add(time.Minute)
	inv.ObserveIEC104(o)
	o.ControlDirection = false
	inv.ObserveIEC104(o) // server command echo is not an attempt
	o.ControlDirection = true
	o.TypeID = 1
	inv.ObserveIEC104(o) // monitoring is not a command
	s := inv.SnapshotIEC104()
	p := s.Pairs[0]
	ca := p.CAs[0]
	if p.AttemptedCommands != 2 || ca.AttemptedCommands != 2 {
		t.Fatalf("counts: %+v / %+v", p, ca)
	}
	if len(ca.Points) != 2 || !ca.Points[1].LastSeen.Equal(o.Time) || !ca.FirstSeen.Before(ca.LastSeen) {
		t.Fatalf("points/times: %+v", ca)
	}
	s.Pairs[0].CAs[0].Points[0].IOA = 999
	if inv.SnapshotIEC104().Pairs[0].CAs[0].Points[0].IOA != 10 {
		t.Fatal("snapshot aliases store")
	}
	inv.Clear()
	s = inv.SnapshotIEC104()
	if len(s.Pairs) != 0 || s.Overflow != (InventoryOverflow{}) {
		t.Fatal(s)
	}
}

func TestIEC104BoundsLRUAndOverflow(t *testing.T) {
	inv := New()
	o := observation()
	inv.ObserveIEC104(o)
	// Reobserve point zero so point one, not zero, is evicted.
	for i := 0; i < MaxIEC104Points; i++ {
		o.IOAs = []uint32{uint32(i)}
		inv.ObserveIEC104(o)
	}
	o.IOAs = []uint32{0}
	inv.ObserveIEC104(o)
	o.IOAs = []uint32{MaxIEC104Points}
	inv.ObserveIEC104(o)
	s := inv.SnapshotIEC104()
	pts := s.Pairs[0].CAs[0].Points
	if len(pts) != MaxIEC104Points || pts[0].IOA != 0 || pts[1].IOA != 2 || s.Overflow.Points != 1 {
		t.Fatalf("points: %d / %+v", len(pts), s.Overflow)
	}
	for i := 2; i <= MaxIEC104CAs+1; i++ {
		o.CA = uint16(i)
		inv.ObserveIEC104(o)
	}
	s = inv.SnapshotIEC104()
	if len(s.Pairs[0].CAs) != MaxIEC104CAs || s.Pairs[0].CAs[0].CA != 2 || s.Overflow.CAs != 1 {
		t.Fatal(s)
	}
	for i := 1; i <= MaxIEC104Pairs; i++ {
		o.Controlling = netip.MustParseAddrPort(fmt.Sprintf("198.51.100.%d:50000", i))
		inv.ObserveIEC104(o)
	}
	s = inv.SnapshotIEC104()
	if len(s.Pairs) != MaxIEC104Pairs || s.Overflow.Pairs != 1 {
		t.Fatalf("pairs: %d / %+v", len(s.Pairs), s.Overflow)
	}
}

func TestInventoryIdleExpiry(t *testing.T) {
	inv := New()
	o := observation()
	inv.ObserveIEC104(o)
	old := time.Now().Add(-MaxIdle)
	inv.iec104.pairs.order.Back().Value.(*entry[pairKey, *pairState]).touched = old
	if len(inv.SnapshotIEC104().Pairs) != 0 {
		t.Fatal("pair did not expire")
	}
	inv.RecordEvent("a", "b", dpi.Event{Proto: "modbus"})
	for _, e := range inv.assets.items {
		e.Value.(*entry[assetKey, *DiscoveredAsset]).touched = old
	}
	if len(inv.List()) != 0 {
		t.Fatal("legacy did not expire")
	}
}

func TestLegacyInventoryBoundsAndCopies(t *testing.T) {
	inv := New()
	ev := dpi.Event{Proto: "dnp3", Attributes: map[string]any{}}
	for i := 0; i < MaxAssets+1; i++ {
		ev.Attributes["source_address"] = uint16(i)
		inv.RecordEvent("client", fmt.Sprintf("peer-%04d", i), ev)
	}
	if len(inv.List()) != MaxAssets {
		t.Fatal("unbounded assets")
	}
	a := inv.GetAssets("client")[0]
	if len(a.Peers) != MaxPeers || len(a.StationAddresses) != MaxStationAddresses {
		t.Fatal("unbounded metadata")
	}
	overflow := inv.SnapshotIEC104().Overflow
	if overflow.Assets != 2 || overflow.Peers == 0 || overflow.StationAddresses == 0 {
		t.Fatal(overflow)
	}
	if len(inv.GetAssets("peer-0000")) != 0 {
		t.Fatal("oldest peer retained")
	}
	a.Peers[0] = "mutated"
	b := inv.GetAssets("client")[0]
	if b.Peers[0] == "mutated" {
		t.Fatal("GetAssets aliases store")
	}
	list := inv.List()
	for i := range list {
		if len(list[i].Peers) > 0 {
			list[i].Peers[0] = "mutated"
		}
	}
	b = inv.GetAssets("client")[0]
	if b.Peers[0] == "mutated" {
		t.Fatal("List aliases store")
	}
}

func TestIEC104BoundedInputAndConcurrentAccess(t *testing.T) {
	inv := New()
	o := observation()
	o.IOAs = make([]uint32, 200)
	inv.ObserveIEC104(o)
	if inv.SnapshotIEC104().Overflow.Points != 73 {
		t.Fatal("oversized ASDU not counted")
	}
	var wg sync.WaitGroup
	for i := 0; i < 4; i++ {
		wg.Go(func() {
			for j := 0; j < 100; j++ {
				inv.ObserveIEC104(o)
				inv.SnapshotIEC104()
				inv.List()
				inv.Clear()
			}
		})
	}
	wg.Wait()
}

func TestIEC104InputsNeverWaitForInventoryLock(t *testing.T) {
	inv := New()
	o := observation()
	inv.ObserveIEC104(o)
	inv.iec104.mu.Lock()
	done := make(chan struct{})
	go func() {
		inv.ObserveIEC104(o)
		close(done)
	}()
	select {
	case <-done:
		inv.iec104.mu.Unlock()
	case <-time.After(time.Second):
		inv.iec104.mu.Unlock()
		<-done
		t.Fatal("inventory inputs blocked")
	}
	s := inv.SnapshotIEC104()
	if s.Overflow.Observations != 1 {
		t.Fatal(s)
	}
}

func TestBoundedObservationRecencyAndExpiry(t *testing.T) {
	b := newBounded[int, int](2)
	var overflow uint64
	at := time.Now()
	add := func(key int, at time.Time) { b.observe(key, at, func() int { return key }, &overflow) }
	add(1, at)
	add(2, at)
	add(1, at.Add(time.Second))
	add(3, at.Add(2*time.Second))
	b.expire(at.Add(3 * time.Second))
	if b.items[2] != nil || overflow != 1 {
		t.Fatal("not LRU", overflow)
	}
	// Reading key one did not refresh its ingestion time.
	if b.items[1] == nil {
		t.Fatal("refreshed key missing")
	}
	b.expire(at.Add(MaxIdle + time.Second))
	if b.items[1] != nil {
		t.Fatal("reads extended retention")
	}
	if b.items[3] == nil {
		t.Fatal("active key expired")
	}
	if overflow != 1 {
		t.Fatal("expiry counted as overflow")
	}
}

func TestIEC104CommandTypesAndInvalidPoints(t *testing.T) {
	commands := map[uint8]bool{}
	for _, id := range []uint8{45, 46, 47, 48, 49, 50, 51, 58, 59, 60, 61, 62, 63, 64} {
		commands[id] = true
	}
	for id := 0; id < 256; id++ {
		if commandType(uint8(id)) != commands[uint8(id)] {
			t.Fatalf("type %d", id)
		}
	}
	inv := New()
	o := observation()
	o.IOAs = []uint32{0xffffff, 0x1000000}
	inv.ObserveIEC104(o)
	s := inv.SnapshotIEC104()
	if s.Overflow.Points != 1 || len(s.Pairs[0].CAs[0].Points) != 1 {
		t.Fatal(s)
	}
}
