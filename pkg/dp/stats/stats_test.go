// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

package stats

import (
	"sync"
	"testing"
	"time"

	"github.com/tonylturner/containd/pkg/dp/dpi"
)

func TestTrackerIndependentPacketAndEventCounters(t *testing.T) {
	tracker := New()
	now := time.Now().UTC()
	tracker.RecordPacket("10.0.0.1", "10.0.0.2", "modbus", 100, now)
	for _, kind := range []string{"read_register", "write_coil", "alert_overflow"} {
		tracker.RecordEvent(dpi.Event{Proto: "modbus", Kind: kind, Timestamp: now.Add(-time.Second),
			Attributes: map[string]any{"src": "event-source", "dst": "event-destination"}})
	}
	got := tracker.Stats()
	if len(got) != 1 {
		t.Fatalf("stats = %+v", got)
	}
	ps := got[0]
	if ps.PacketCount != 1 || ps.ByteCount != 100 || ps.EventCount != 3 || ps.ReadCount != 1 || ps.WriteCount != 1 || ps.AlertCount != 1 || !ps.LastSeen.Equal(now) {
		t.Fatalf("independent counters = %+v", ps)
	}
	top := tracker.TopTalkers(0)
	if len(top) != 1 || top[0].SrcIP != "10.0.0.1" || top[0].Packets != 1 || top[0].Bytes != 100 {
		t.Fatalf("event attributes duplicated/changed packet flow: %+v", top)
	}
}

func TestTrackerEventsWithoutPackets(t *testing.T) {
	tracker := New()
	now := time.Now().UTC()
	for _, attrs := range []map[string]any{nil, {"is_write": true}, {"is_write": " TRUE "}, {"is_write": 1}} {
		tracker.RecordEvent(dpi.Event{Kind: "object", Timestamp: now, Attributes: attrs})
	}
	got := tracker.Stats()[0]
	if got.Protocol != "unknown" || got.PacketCount != 0 || got.ByteCount != 0 || got.EventCount != 4 || got.ReadCount != 2 || got.WriteCount != 2 || !got.LastSeen.Equal(now) {
		t.Fatalf("event-only stats = %+v", got)
	}
	if top := tracker.TopTalkers(1); len(top) != 0 {
		t.Fatalf("event-only flows = %+v", top)
	}
}

func TestTrackerPacketsWithoutEventsAndTopTalkers(t *testing.T) {
	tracker := New()
	now := time.Now().UTC()
	for i := 0; i < 5; i++ {
		tracker.RecordPacket("a", "b", "modbus", 100, now)
	}
	for i := 0; i < 3; i++ {
		tracker.RecordPacket("c", "d", "http", 50, now)
	}
	tracker.RecordPacket("", "", "", 0, now)
	got := tracker.Stats()
	if len(got) != 3 || got[0].Protocol != "modbus" || got[0].PacketCount != 5 || got[0].ByteCount != 500 || got[0].EventCount != 0 {
		t.Fatalf("packet-only stats = %+v", got)
	}
	top := tracker.TopTalkers(0)
	if len(top) != 2 || top[0].SrcIP != "a" || top[0].Bytes != 500 || top[0].Packets != 5 || top[1].Bytes != 150 {
		t.Fatalf("top talkers = %+v", top)
	}
	if top := tracker.TopTalkers(1); len(top) != 1 {
		t.Fatalf("top 1 = %+v", top)
	}
}

func TestTrackerConcurrentAccounting(t *testing.T) {
	tracker := New()
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Go(func() {
			for j := 0; j < 100; j++ {
				tracker.RecordPacket("a", "b", "test", 10, time.Now())
				tracker.RecordEvent(dpi.Event{Proto: "test", Kind: "read"})
				tracker.Stats()
				tracker.TopTalkers(1)
			}
		})
	}
	wg.Wait()
	got := tracker.Stats()[0]
	if got.PacketCount != 800 || got.ByteCount != 8000 || got.EventCount != 800 {
		t.Fatalf("concurrent stats = %+v", got)
	}
}

func TestNilTracker(t *testing.T) {
	var tracker *Tracker
	tracker.RecordEvent(dpi.Event{Proto: "test"})
	tracker.RecordPacket("a", "b", "tcp", 1, time.Now())
	if s := tracker.Stats(); s != nil {
		t.Fatalf("expected nil stats, got %v", s)
	}
	if tt := tracker.TopTalkers(5); tt != nil {
		t.Fatalf("expected nil top talkers, got %v", tt)
	}
}
