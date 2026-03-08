// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

package inventory

import (
	"testing"
	"time"

	"github.com/tonylturner/containd/pkg/dp/dpi"
)

func TestRecordModbusCreatesAssets(t *testing.T) {
	inv := New()
	ev := dpi.Event{
		Proto:     "modbus",
		Kind:      "request",
		Timestamp: time.Now().UTC(),
		Attributes: map[string]any{
			"unit_id":       uint8(1),
			"function_code": uint8(3),
			"is_write":      false,
		},
	}
	inv.RecordEvent("10.0.0.1", "10.0.0.2", ev)

	assets := inv.List()
	if len(assets) != 2 {
		t.Fatalf("expected 2 assets, got %d", len(assets))
	}

	src, ok := inv.Get("10.0.0.1")
	if !ok {
		t.Fatal("expected source asset")
	}
	if src.Role != "master" {
		t.Errorf("expected master role, got %s", src.Role)
	}
	if src.Protocol != "modbus" {
		t.Errorf("expected modbus protocol, got %s", src.Protocol)
	}

	dst, ok := inv.Get("10.0.0.2")
	if !ok {
		t.Fatal("expected destination asset")
	}
	if dst.Role != "slave" {
		t.Errorf("expected slave role, got %s", dst.Role)
	}
}

func TestRecordModbusRoleClassification(t *testing.T) {
	inv := New()
	ev := dpi.Event{
		Proto:     "modbus",
		Kind:      "request",
		Timestamp: time.Now().UTC(),
		Attributes: map[string]any{
			"unit_id":       uint8(2),
			"function_code": uint8(16),
			"is_write":      true,
		},
	}
	inv.RecordEvent("192.168.1.10", "192.168.1.20", ev)

	master, _ := inv.Get("192.168.1.10")
	if master.Role != "master" {
		t.Errorf("source should be master, got %s", master.Role)
	}
	slave, _ := inv.Get("192.168.1.20")
	if slave.Role != "slave" {
		t.Errorf("destination should be slave, got %s", slave.Role)
	}
}

func TestListReturnsAllAssets(t *testing.T) {
	inv := New()
	now := time.Now().UTC()

	for i, ip := range []string{"10.0.0.1", "10.0.0.2", "10.0.0.3"} {
		ev := dpi.Event{
			Proto:     "modbus",
			Timestamp: now,
			Attributes: map[string]any{
				"unit_id":       uint8(i + 1),
				"function_code": uint8(3),
			},
		}
		inv.RecordEvent(ip, "10.0.0.100", ev)
	}

	assets := inv.List()
	// 3 sources + 1 destination = 4
	if len(assets) != 4 {
		t.Fatalf("expected 4 assets, got %d", len(assets))
	}
}

func TestDeduplicationOfFunctionCodesAndUnitIDs(t *testing.T) {
	inv := New()
	now := time.Now().UTC()

	// Send same event twice.
	ev := dpi.Event{
		Proto:     "modbus",
		Timestamp: now,
		Attributes: map[string]any{
			"unit_id":       uint8(1),
			"function_code": uint8(3),
		},
	}
	inv.RecordEvent("10.0.0.1", "10.0.0.2", ev)
	inv.RecordEvent("10.0.0.1", "10.0.0.2", ev)

	src, _ := inv.Get("10.0.0.1")
	if len(src.UnitIDs) != 1 {
		t.Errorf("expected 1 unique unit ID, got %d", len(src.UnitIDs))
	}
	if len(src.FunctionCodes) != 1 {
		t.Errorf("expected 1 unique function code, got %d", len(src.FunctionCodes))
	}
	if src.PacketCount != 2 {
		t.Errorf("expected packet count 2, got %d", src.PacketCount)
	}

	// Add a different function code.
	ev2 := dpi.Event{
		Proto:     "modbus",
		Timestamp: now,
		Attributes: map[string]any{
			"unit_id":       uint8(1),
			"function_code": uint8(16),
		},
	}
	inv.RecordEvent("10.0.0.1", "10.0.0.2", ev2)

	src, _ = inv.Get("10.0.0.1")
	if len(src.FunctionCodes) != 2 {
		t.Errorf("expected 2 unique function codes, got %d", len(src.FunctionCodes))
	}
	if len(src.UnitIDs) != 1 {
		t.Errorf("expected 1 unique unit ID after same unit, got %d", len(src.UnitIDs))
	}
}

func TestRecordDNP3(t *testing.T) {
	inv := New()
	ev := dpi.Event{
		Proto:     "dnp3",
		Kind:      "request",
		Timestamp: time.Now().UTC(),
		Attributes: map[string]any{
			"function_code":       uint8(1),
			"source_address":      uint16(2),
			"destination_address": uint16(1),
		},
	}
	inv.RecordEvent("10.0.0.1", "10.0.0.2", ev)

	src, ok := inv.Get("10.0.0.1")
	if !ok {
		t.Fatal("expected source asset")
	}
	if src.Protocol != "dnp3" {
		t.Errorf("expected dnp3, got %s", src.Protocol)
	}
	if len(src.StationAddresses) != 1 || src.StationAddresses[0] != 2 {
		t.Errorf("expected station address 2, got %v", src.StationAddresses)
	}
}

func TestRecordCIP(t *testing.T) {
	inv := New()
	ev := dpi.Event{
		Proto:     "cip",
		Kind:      "request",
		Timestamp: time.Now().UTC(),
		Attributes: map[string]any{
			"service_code": uint8(0x4C),
		},
	}
	inv.RecordEvent("10.0.0.1", "10.0.0.2", ev)

	src, ok := inv.Get("10.0.0.1")
	if !ok {
		t.Fatal("expected source asset")
	}
	if src.Role != "client" {
		t.Errorf("expected client role, got %s", src.Role)
	}
	dst, ok := inv.Get("10.0.0.2")
	if !ok {
		t.Fatal("expected destination asset")
	}
	if dst.Role != "server" {
		t.Errorf("expected server role, got %s", dst.Role)
	}
}

func TestClear(t *testing.T) {
	inv := New()
	ev := dpi.Event{
		Proto:     "modbus",
		Timestamp: time.Now().UTC(),
		Attributes: map[string]any{
			"unit_id":       uint8(1),
			"function_code": uint8(3),
		},
	}
	inv.RecordEvent("10.0.0.1", "10.0.0.2", ev)
	if len(inv.List()) == 0 {
		t.Fatal("expected assets before clear")
	}
	inv.Clear()
	if len(inv.List()) != 0 {
		t.Fatal("expected no assets after clear")
	}
}

func TestPeers(t *testing.T) {
	inv := New()
	now := time.Now().UTC()
	ev := dpi.Event{
		Proto:     "modbus",
		Timestamp: now,
		Attributes: map[string]any{
			"unit_id":       uint8(1),
			"function_code": uint8(3),
		},
	}
	inv.RecordEvent("10.0.0.1", "10.0.0.2", ev)
	inv.RecordEvent("10.0.0.1", "10.0.0.3", ev)

	src, _ := inv.Get("10.0.0.1")
	if len(src.Peers) != 2 {
		t.Errorf("expected 2 peers, got %d", len(src.Peers))
	}

	// Duplicate peer should not be added.
	inv.RecordEvent("10.0.0.1", "10.0.0.2", ev)
	src, _ = inv.Get("10.0.0.1")
	if len(src.Peers) != 2 {
		t.Errorf("expected 2 peers after dup, got %d", len(src.Peers))
	}
}

func TestNonICSEventIgnored(t *testing.T) {
	inv := New()
	ev := dpi.Event{
		Proto:     "http",
		Kind:      "request",
		Timestamp: time.Now().UTC(),
		Attributes: map[string]any{
			"method": "GET",
		},
	}
	inv.RecordEvent("10.0.0.1", "10.0.0.2", ev)
	if len(inv.List()) != 0 {
		t.Fatal("non-ICS events should be ignored")
	}
}
