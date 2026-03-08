// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

package anomaly

import (
	"testing"
	"time"

	"github.com/tonylturner/containd/pkg/dp/dpi"
)

func TestWriteRateAnomalyDetection(t *testing.T) {
	d := New(WithWriteRateThreshold(5), WithTotalRateThreshold(10000))

	src, dst := "10.0.0.1", "10.0.0.2"
	now := time.Now()

	// Send 5 write events — should not trigger (threshold is 5, so >5 triggers).
	for i := 0; i < 5; i++ {
		ev := dpi.Event{
			Proto:      "modbus",
			Kind:       "request",
			Attributes: map[string]any{"is_write": true, "function_code": 6},
			Timestamp:  now,
		}
		anomalies := d.Check(src, dst, ev)
		for _, a := range anomalies {
			if a.Type == "rate_anomaly" && a.Attributes["kind"] == "write" {
				t.Fatalf("unexpected write rate anomaly after %d events", i+1)
			}
		}
	}

	// The 6th write should trigger the anomaly.
	ev := dpi.Event{
		Proto:      "modbus",
		Kind:       "request",
		Attributes: map[string]any{"is_write": true, "function_code": 6},
		Timestamp:  now,
	}
	anomalies := d.Check(src, dst, ev)
	found := false
	for _, a := range anomalies {
		if a.Type == "rate_anomaly" && a.Attributes["kind"] == "write" {
			found = true
			if a.Severity != "critical" {
				t.Errorf("expected critical severity, got %s", a.Severity)
			}
		}
	}
	if !found {
		t.Fatal("expected write rate anomaly after exceeding threshold")
	}
}

func TestModbusInvalidFunctionCode(t *testing.T) {
	d := New()

	src, dst := "10.0.0.1", "10.0.0.2"
	ev := dpi.Event{
		Proto: "modbus",
		Kind:  "request",
		Attributes: map[string]any{
			"function_code": 128,
		},
		Timestamp: time.Now(),
	}
	anomalies := d.Check(src, dst, ev)

	found := false
	for _, a := range anomalies {
		if a.Type == "protocol_violation" && a.Protocol == "modbus" {
			found = true
			if a.Severity != "high" {
				t.Errorf("expected high severity, got %s", a.Severity)
			}
		}
	}
	if !found {
		t.Fatal("expected protocol violation for invalid function code >= 128")
	}
}

func TestModbusResponseWithoutRequest(t *testing.T) {
	d := New()

	// Send a response without a prior request.
	ev := dpi.Event{
		Proto: "modbus",
		Kind:  "response",
		Attributes: map[string]any{
			"transaction_id": uint16(42),
			"function_code":  3,
		},
		Timestamp: time.Now(),
	}
	anomalies := d.Check("10.0.0.2", "10.0.0.1", ev)

	found := false
	for _, a := range anomalies {
		if a.Type == "protocol_violation" && a.Message != "" {
			found = true
		}
	}
	if !found {
		t.Fatal("expected protocol violation for response without request")
	}
}

func TestModbusResponseMatchesRequest(t *testing.T) {
	d := New()

	src, dst := "10.0.0.1", "10.0.0.2"

	// Send a request.
	reqEv := dpi.Event{
		Proto: "modbus",
		Kind:  "request",
		Attributes: map[string]any{
			"transaction_id": uint16(42),
			"function_code":  3,
		},
		Timestamp: time.Now(),
	}
	d.Check(src, dst, reqEv)

	// Send a matching response (from dst back to src).
	respEv := dpi.Event{
		Proto: "modbus",
		Kind:  "response",
		Attributes: map[string]any{
			"transaction_id": uint16(42),
			"function_code":  3,
		},
		Timestamp: time.Now(),
	}
	anomalies := d.Check(dst, src, respEv)

	for _, a := range anomalies {
		if a.Type == "protocol_violation" && a.Message != "" {
			if a.Attributes["transaction_id"] == uint16(42) {
				t.Fatal("should not flag a response that matches a prior request")
			}
		}
	}
}

func TestRateTrackerBucketRollover(t *testing.T) {
	rt := newRateTracker()

	base := time.Date(2025, 1, 1, 12, 0, 0, 0, time.UTC)

	// Record 10 events in minute 0.
	for i := 0; i < 10; i++ {
		rt.recordAt("flow1", base)
	}

	// In minute 1, the sliding window should include minute 0's events.
	t1 := base.Add(1 * time.Minute)
	count := rt.recordAt("flow1", t1)
	// Should be 10 (from prev minute) + 1 (current) = 11.
	if count != 11 {
		t.Errorf("expected 11, got %d", count)
	}

	// In minute 2, minute 0 is no longer "previous minute".
	t2 := base.Add(2 * time.Minute)
	count = rt.recordAt("flow1", t2)
	// Previous minute (minute 1) had 1 event, current has 1 = 2.
	if count != 2 {
		t.Errorf("expected 2, got %d", count)
	}

	// After 6 minutes, old buckets should be GC'd.
	t6 := base.Add(7 * time.Minute)
	rt.recordAt("flow1", t6)
	if len(rt.buckets["flow1"]) > 5 {
		t.Errorf("expected at most 5 minute buckets, got %d", len(rt.buckets["flow1"]))
	}
}

func TestAnomalyRingBuffer(t *testing.T) {
	d := New(WithWriteRateThreshold(0), WithTotalRateThreshold(1000000))

	src, dst := "10.0.0.1", "10.0.0.2"

	// Generate anomalies by sending write events that exceed threshold of 0.
	for i := 0; i < 10; i++ {
		ev := dpi.Event{
			Proto:      "modbus",
			Kind:       "request",
			Attributes: map[string]any{"is_write": true, "function_code": 6},
			Timestamp:  time.Now(),
		}
		d.Check(src, dst, ev)
	}

	// Should have anomalies in the ring buffer.
	all := d.Anomalies(0)
	if len(all) == 0 {
		t.Fatal("expected anomalies in ring buffer")
	}

	// Test limit.
	limited := d.Anomalies(3)
	if len(limited) != 3 {
		t.Fatalf("expected 3 anomalies with limit, got %d", len(limited))
	}

	// Most recent should be first.
	if limited[0].Timestamp.Before(limited[2].Timestamp) {
		t.Error("expected most recent anomaly first")
	}

	// Clear should reset everything.
	d.Clear()
	after := d.Anomalies(0)
	if len(after) != 0 {
		t.Errorf("expected 0 anomalies after clear, got %d", len(after))
	}
}

func TestBroadcastUnitIDWrite(t *testing.T) {
	d := New()

	ev := dpi.Event{
		Proto: "modbus",
		Kind:  "request",
		Attributes: map[string]any{
			"function_code": 6,
			"unit_id":       0,
			"is_write":      true,
		},
		Timestamp: time.Now(),
	}
	anomalies := d.Check("10.0.0.1", "10.0.0.2", ev)

	found := false
	for _, a := range anomalies {
		if a.Type == "protocol_violation" && a.Protocol == "modbus" {
			if a.Message == "Broadcast unit ID 0 used for write operation" {
				found = true
			}
		}
	}
	if !found {
		t.Fatal("expected protocol violation for broadcast unit ID on write")
	}
}

func TestMalformedFrameDetection(t *testing.T) {
	d := New()

	ev := dpi.Event{
		Proto: "modbus",
		Kind:  "request",
		Attributes: map[string]any{
			"error": "incomplete MBAP header",
		},
		Timestamp: time.Now(),
	}
	anomalies := d.Check("10.0.0.1", "10.0.0.2", ev)

	found := false
	for _, a := range anomalies {
		if a.Type == "malformed_frame" {
			found = true
			if a.Severity != "medium" {
				t.Errorf("expected medium severity, got %s", a.Severity)
			}
		}
	}
	if !found {
		t.Fatal("expected malformed_frame anomaly for event with error attribute")
	}
}
