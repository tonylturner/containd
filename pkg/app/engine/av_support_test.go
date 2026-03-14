// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

package engineapp

import (
	"context"
	"testing"
	"time"

	"github.com/tonylturner/containd/pkg/cp/config"
	"github.com/tonylturner/containd/pkg/cp/services"
	dpengine "github.com/tonylturner/containd/pkg/dp/engine"
)

func TestAVSinkAdapterHelpers(t *testing.T) {
	t.Parallel()

	if err := (&avSinkAdapter{}).ApplyAVConfig(context.Background(), config.AVConfig{}); err == nil {
		t.Fatal("expected nil adapter to reject ApplyAVConfig")
	}
	if gotSrc, gotDst, gotPort, gotProto := parseHostPort("10.0.0.1:1234", "10.0.0.2:8443"); gotSrc == nil || gotDst == nil || gotPort != "8443" || gotProto != "tcp" {
		t.Fatalf("parseHostPort = %v %v %q %q", gotSrc, gotDst, gotPort, gotProto)
	}

	avMgr := services.NewAVManager()
	adapter := &avSinkAdapter{av: avMgr}
	adapter.EnqueueAVScan(context.Background(), dpengine.AVScanTask{
		Hash:      "sha256:abc",
		Proto:     "http",
		Source:    "10.0.0.1:1234",
		Dest:      "10.0.0.2:8443",
		Direction: "outbound",
		FlowID:    "flow-1",
	})
	if avMgr.Current().Enabled {
		t.Fatal("unexpected AV config mutation from enqueue")
	}
	if avMgr.Status()["queue_depth"] == nil {
		t.Fatalf("expected queue depth in AV status: %#v", avMgr.Status())
	}
	if got := avMgr.Status()["queue_depth"]; got != 1 {
		t.Fatalf("queue_depth = %#v, want 1", got)
	}

	cfg := config.AVConfig{Enabled: true, Mode: "icap", FailOpenICS: true, BlockTTL: 30}
	if err := adapter.ApplyAVConfig(context.Background(), cfg); err != nil {
		t.Fatalf("ApplyAVConfig: %v", err)
	}
	if got := avMgr.Current(); !got.Enabled || got.Mode != "icap" {
		t.Fatalf("unexpected AV config after apply: %#v", got)
	}
}

func TestWireAVEventsAndVerdicts(t *testing.T) {
	t.Parallel()

	dp, err := dpengine.New(dpengine.Config{})
	if err != nil {
		t.Fatalf("engine.New: %v", err)
	}
	avMgr := services.NewAVManager()
	adapter := &avSinkAdapter{av: avMgr, dp: dp}
	dp.SetAVSink(adapter)
	if err := adapter.ApplyAVConfig(context.Background(), config.AVConfig{Enabled: true, FailOpenICS: true, BlockTTL: 30}); err != nil {
		t.Fatalf("ApplyAVConfig: %v", err)
	}

	wireAVEvents(avMgr, dp)
	if avMgr.OnEvent == nil || avMgr.OnVerdict == nil {
		t.Fatal("expected AV callbacks to be wired")
	}
	avMgr.OnEvent("service.av.updated", map[string]any{"enabled": true})
	events := dp.Events().List(10)
	if len(events) == 0 || events[len(events)-1].Kind != "service.av.updated" {
		t.Fatalf("unexpected AV event list: %#v", events)
	}

	handleAVVerdict(dp, services.ScanTask{
		Hash:    "sha256:def",
		Proto:   "http",
		Source:  "10.0.0.1:1234",
		Dest:    "10.0.0.2:8443",
		Metadata: map[string]any{"flow_id": "flow-2"},
	}, services.ScanResult{Verdict: "clean"})

	before := len(dp.Events().List(20))
	handleAVVerdict(dp, services.ScanTask{
		Hash:     "sha256:ghi",
		Proto:    "modbus",
		Source:   "10.0.0.3:502",
		Dest:     "10.0.0.4:1502",
		ICS:      true,
		Metadata: map[string]any{"flow_id": "flow-3"},
	}, services.ScanResult{Verdict: "malware"})

	deadline := time.Now().Add(500 * time.Millisecond)
	for len(dp.Events().List(20)) <= before && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	events = dp.Events().List(20)
	foundBypass := false
	for _, ev := range events {
		if ev.Kind == "service.av.bypass_ics" {
			foundBypass = true
			break
		}
	}
	if !foundBypass {
		t.Fatalf("expected ICS bypass AV event, got %#v", events)
	}
}
