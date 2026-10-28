// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 containd Authors

package inventory

import (
	"reflect"
	"testing"
	"time"

	"github.com/tonylturner/containd/pkg/dp/dpi"
)

func TestInventoryObservationIdentity(t *testing.T) {
	const ip = "10.0.0.1"
	at := time.Now().UTC()
	inv := New()
	want := []DiscoveredAsset{}
	for _, tc := range []struct {
		proto                string
		port                 uint16
		initiator, responder string
	}{
		{"cip", 44818, "client", "server"},
		{"dnp3", 20000, "master", "slave"},
		{"modbus", 502, "master", "slave"},
	} {
		record := func(peer string, marker uint8, role string, when time.Time) {
			key := inventoryKey(ip, peer, tc.port)
			if role == tc.responder {
				key = inventoryKey(peer, ip, tc.port).Reversed()
			}
			id := key.Hash()
			if role == "" {
				id = ""
			}
			inv.RecordEvent(ip, peer, dpi.Event{Proto: tc.proto, FlowID: id, Timestamp: when, Attributes: map[string]any{
				"unit_id": marker, "function_code": marker, "service_code": marker,
				"source_address": uint16(marker), "destination_address": uint16(100 + marker),
			}})
		}
		// Reply-first evidence is kept separate from initiating observations.
		record("10.0.0.3", 2, tc.responder, at.Add(time.Second))
		record("10.0.0.4", 3, "", at.Add(2*time.Second))
		record("10.0.0.2", 1, tc.initiator, at)
		record("10.0.0.5", 4, tc.initiator, at.Add(3*time.Second))
		for _, role := range []string{"", tc.initiator, tc.responder} {
			a := DiscoveredAsset{IP: ip, Protocol: tc.proto, Role: role, PacketCount: 1}
			switch role {
			case "":
				a.FirstSeen, a.LastSeen = at.Add(2*time.Second), at.Add(2*time.Second)
				a.FunctionCodes, a.Peers = []uint8{3}, []string{"10.0.0.4"}
			case tc.initiator:
				a.FirstSeen, a.LastSeen = at, at.Add(3*time.Second)
				a.FunctionCodes, a.Peers = []uint8{1, 4}, []string{"10.0.0.2", "10.0.0.5"}
				a.PacketCount = 2
			case tc.responder:
				a.FirstSeen, a.LastSeen = at.Add(time.Second), at.Add(time.Second)
				a.FunctionCodes, a.Peers = []uint8{2}, []string{"10.0.0.3"}
			}
			if tc.proto == "modbus" {
				a.UnitIDs = append([]uint8(nil), a.FunctionCodes...)
			}
			if tc.proto == "dnp3" {
				for _, code := range a.FunctionCodes {
					a.StationAddresses = append(a.StationAddresses, uint16(code))
				}
			}
			want = append(want, a)
		}
	}
	for range 10 {
		if got := inv.GetAssets(ip); !reflect.DeepEqual(got, want) {
			t.Fatalf("observations:\n got %+v\nwant %+v", got, want)
		}
	}
	list := inv.List()
	if len(list) != 21 || !reflect.DeepEqual(list[:len(want)], want) {
		t.Fatalf("list and lookup disagree: %+v", list)
	}
	for i := 1; i < len(list); i++ {
		a, b := list[i-1], list[i]
		if a.IP > b.IP || (a.IP == b.IP && (a.Protocol > b.Protocol ||
			(a.Protocol == b.Protocol && a.Role >= b.Role))) {
			t.Fatalf("list is not sorted: %+v then %+v", a, b)
		}
	}
	for _, snapshot := range [][]DiscoveredAsset{inv.GetAssets(ip), inv.List()} {
		for i := range snapshot {
			a := &snapshot[i]
			a.Role, a.PacketCount = "mutated", -1
			for j := range a.UnitIDs {
				a.UnitIDs[j] = 255
			}
			for j := range a.FunctionCodes {
				a.FunctionCodes[j] = 255
			}
			for j := range a.StationAddresses {
				a.StationAddresses[j] = 65535
			}
			for j := range a.Peers {
				a.Peers[j] = "mutated"
			}
		}
		if !reflect.DeepEqual(inv.GetAssets(ip), want) {
			t.Fatal("snapshot aliases observation metadata")
		}
	}
	if got := inv.GetAssets("missing"); got == nil || len(got) != 0 {
		t.Fatalf("missing lookup: %+v", got)
	}
	inv.Clear()
	if len(inv.GetAssets(ip)) != 0 || len(inv.List()) != 0 {
		t.Fatal("Clear retained observations")
	}
}

func TestInventoryObservationBucketRetention(t *testing.T) {
	inv := New()
	inv.assets = newBounded[assetKey, *DiscoveredAsset](3)
	now := time.Now()
	observe := func(proto, role string) {
		inv.mu.Lock()
		defer inv.mu.Unlock()
		inv.getOrCreate("10.0.0.1", proto, role, now)
	}
	observe("modbus", "master")
	observe("modbus", "slave")
	observe("cip", "client")
	// A read must not refresh the oldest bucket's ingestion recency.
	inv.GetAssets("10.0.0.1")
	observe("modbus", "")
	got := inv.GetAssets("10.0.0.1")
	if len(got) != 3 || got[1].Role != "" || got[2].Role != "slave" || inv.overflow.Assets != 1 {
		t.Fatalf("bucket eviction: %+v / %+v", got, inv.overflow)
	}
	// Expire just the oldest remaining bucket, not every observation of its IP.
	inv.assets.order.Back().Value.(*entry[assetKey, *DiscoveredAsset]).touched = time.Now().Add(-MaxIdle)
	got = inv.GetAssets("10.0.0.1")
	if len(got) != 2 || got[1].Role != "" || inv.overflow.Assets != 1 {
		t.Fatalf("bucket expiry: %+v / %+v", got, inv.overflow)
	}
	inv.Clear()
	if inv.overflow != (InventoryOverflow{}) || inv.assets.cap != MaxAssets {
		t.Fatal("Clear did not restore bounds and counters")
	}
}
