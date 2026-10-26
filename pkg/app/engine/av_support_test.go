// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

package engineapp

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/tonylturner/containd/pkg/cp/config"
	"github.com/tonylturner/containd/pkg/cp/services"
	dpengine "github.com/tonylturner/containd/pkg/dp/engine"
	"go.uber.org/zap"
)

type failingAVApplier struct{ applied int }

func (f *failingAVApplier) Apply(context.Context, config.AVConfig) error {
	f.applied++
	return errors.New("clamd not ready")
}

func TestServicesApplyReportsAVFailure(t *testing.T) {
	dp, err := dpengine.New(dpengine.Config{})
	if err != nil {
		t.Fatal(err)
	}
	av := &failingAVApplier{}
	rec := httptest.NewRecorder()
	servicesHandler(zap.NewNop().Sugar(), dp, nil, nil, av).ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/internal/services", strings.NewReader(`{}`)))
	if av.applied != 1 {
		t.Fatalf("AV applied %d times, want 1", av.applied)
	}
	if runtime.GOOS != "linux" {
		// WireGuard cannot apply off Linux and is reported first.
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("non-linux services apply = %d %s", rec.Code, rec.Body)
		}
		return
	}
	if rec.Code != http.StatusServiceUnavailable || !strings.Contains(rec.Body.String(), "AV service apply failed: clamd not ready") {
		t.Fatalf("AV failure was hidden: %d %s", rec.Code, rec.Body)
	}
}

func TestAVSinkAdapterHelpers(t *testing.T) {
	if gotSrc, gotDst, gotPort, gotProto := parseHostPort("10.0.0.1:1234", "10.0.0.2:8443"); gotSrc == nil || gotDst == nil || gotPort != "8443" || gotProto != "tcp" {
		t.Fatalf("parseHostPort = %v %v %q %q", gotSrc, gotDst, gotPort, gotProto)
	}

	avMgr := services.NewAVManager(context.Background(), services.AVOptions{StateDir: t.TempDir(), DatabaseDir: t.TempDir()})
	t.Cleanup(func() { _ = avMgr.Stop() })
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
	if got := avMgr.Status(context.Background())["queue_depth"]; got != 1 {
		t.Fatalf("queue_depth = %#v, want 1", got)
	}
}

func TestWireAVEventsAndVerdicts(t *testing.T) {
	t.Parallel()

	dp, err := dpengine.New(dpengine.Config{})
	if err != nil {
		t.Fatalf("engine.New: %v", err)
	}
	avMgr := services.NewAVManager(context.Background(), services.AVOptions{StateDir: t.TempDir(), DatabaseDir: t.TempDir()})
	t.Cleanup(func() { _ = avMgr.Stop() })
	dp.SetAVSink(&avSinkAdapter{av: avMgr})
	cfg := config.AVConfig{Enabled: false, FailOpenICS: true, BlockTTL: 30}
	if err := avMgr.Apply(context.Background(), cfg); err != nil {
		t.Fatalf("Apply: %v", err)
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

	handleAVVerdict(dp, cfg, services.ScanTask{
		Hash:     "sha256:def",
		Proto:    "http",
		Source:   "10.0.0.1:1234",
		Dest:     "10.0.0.2:8443",
		Metadata: map[string]any{"flow_id": "flow-2"},
	}, services.ScanResult{Verdict: "clean"})

	before := len(dp.Events().List(20))
	handleAVVerdict(dp, cfg, services.ScanTask{
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
