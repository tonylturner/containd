// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

package stats

import (
	"testing"
	"time"

	"github.com/tonylturner/containd/pkg/dp/dpi"
)

func TestTrackerRecordAndStats(t *testing.T) {
	tracker := New()

	ev1 := dpi.Event{
		Proto:     "modbus",
		Kind:      "read_register",
		Timestamp: time.Now(),
		Attributes: map[string]any{
			"src": "10.0.0.1",
			"dst": "10.0.0.2",
		},
	}
	ev2 := dpi.Event{
		Proto:     "modbus",
		Kind:      "write_coil",
		Timestamp: time.Now(),
		Attributes: map[string]any{
			"src": "10.0.0.1",
			"dst": "10.0.0.2",
		},
	}
	ev3 := dpi.Event{
		Proto:     "http",
		Kind:      "request",
		Timestamp: time.Now(),
	}

	tracker.Record(ev1, 100)
	tracker.Record(ev2, 200)
	tracker.Record(ev3, 50)

	stats := tracker.Stats()
	if len(stats) != 2 {
		t.Fatalf("expected 2 protocols, got %d", len(stats))
	}
	// Should be sorted by packet count descending; modbus has 2.
	if stats[0].Protocol != "modbus" {
		t.Fatalf("expected modbus first, got %s", stats[0].Protocol)
	}
	if stats[0].PacketCount != 2 {
		t.Fatalf("expected 2 packets for modbus, got %d", stats[0].PacketCount)
	}
	if stats[0].ByteCount != 300 {
		t.Fatalf("expected 300 bytes for modbus, got %d", stats[0].ByteCount)
	}
	if stats[0].ReadCount != 1 {
		t.Fatalf("expected 1 read for modbus, got %d", stats[0].ReadCount)
	}
	if stats[0].WriteCount != 1 {
		t.Fatalf("expected 1 write for modbus, got %d", stats[0].WriteCount)
	}
}

func TestTrackerAlertCounting(t *testing.T) {
	tracker := New()
	ev := dpi.Event{
		Proto:     "modbus",
		Kind:      "alert_overflow",
		Timestamp: time.Now(),
	}
	tracker.Record(ev, 10)
	stats := tracker.Stats()
	if len(stats) != 1 {
		t.Fatalf("expected 1 protocol, got %d", len(stats))
	}
	if stats[0].AlertCount != 1 {
		t.Fatalf("expected 1 alert, got %d", stats[0].AlertCount)
	}
}

func TestTrackerTopTalkers(t *testing.T) {
	tracker := New()

	// Create events with different src/dst to populate flow stats.
	for i := 0; i < 5; i++ {
		ev := dpi.Event{
			Proto:     "modbus",
			Kind:      "request",
			Timestamp: time.Now(),
			Attributes: map[string]any{
				"src": "10.0.0.1",
				"dst": "10.0.0.2",
			},
		}
		tracker.Record(ev, 100)
	}
	for i := 0; i < 3; i++ {
		ev := dpi.Event{
			Proto:     "http",
			Kind:      "request",
			Timestamp: time.Now(),
			Attributes: map[string]any{
				"src": "10.0.0.3",
				"dst": "10.0.0.4",
			},
		}
		tracker.Record(ev, 50)
	}

	top := tracker.TopTalkers(10)
	if len(top) != 2 {
		t.Fatalf("expected 2 flows, got %d", len(top))
	}
	// First should be the higher byte flow (10.0.0.1->10.0.0.2, 500 bytes).
	if top[0].SrcIP != "10.0.0.1" {
		t.Fatalf("expected top talker src 10.0.0.1, got %s", top[0].SrcIP)
	}
	if top[0].Bytes != 500 {
		t.Fatalf("expected 500 bytes, got %d", top[0].Bytes)
	}

	// TopTalkers with n=1 should return just one.
	top1 := tracker.TopTalkers(1)
	if len(top1) != 1 {
		t.Fatalf("expected 1 top talker, got %d", len(top1))
	}
}

func TestTrackerRecordFlow(t *testing.T) {
	tracker := New()
	tracker.RecordFlow("10.0.0.1", "10.0.0.2", "tcp", 100, 5000)
	tracker.RecordFlow("10.0.0.1", "10.0.0.2", "tcp", 50, 2500)

	top := tracker.TopTalkers(10)
	if len(top) != 1 {
		t.Fatalf("expected 1 flow, got %d", len(top))
	}
	if top[0].Packets != 150 {
		t.Fatalf("expected 150 packets, got %d", top[0].Packets)
	}
	if top[0].Bytes != 7500 {
		t.Fatalf("expected 7500 bytes, got %d", top[0].Bytes)
	}
}

func TestNilTracker(t *testing.T) {
	var tracker *Tracker
	tracker.Record(dpi.Event{Proto: "test", Kind: "test", Timestamp: time.Now()}, 10)
	tracker.RecordFlow("a", "b", "tcp", 1, 1)
	if s := tracker.Stats(); s != nil {
		t.Fatalf("expected nil stats, got %v", s)
	}
	if tt := tracker.TopTalkers(5); tt != nil {
		t.Fatalf("expected nil top talkers, got %v", tt)
	}
}
