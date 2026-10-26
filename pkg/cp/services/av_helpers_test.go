// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

package services

import (
	"context"
	"errors"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/tonylturner/containd/pkg/cp/config"
	"go.uber.org/zap"
)

func TestAVManagerApplyStatusAndFreshclamGuards(t *testing.T) {
	mgr := NewAVManager()
	mgr.log = zap.NewNop().Sugar()

	var emitted []string
	mgr.OnEvent = func(kind string, attrs map[string]any) {
		emitted = append(emitted, kind)
	}

	cfg := config.AVConfig{
		Enabled:      true,
		Mode:         "icap",
		MaxSizeBytes: 2048,
		ICAP: config.ICAPConfig{
			Servers: []config.ICAPServer{{Address: "127.0.0.1:13440", Service: "respmod"}},
		},
	}
	if err := mgr.Apply(context.Background(), cfg); err != nil {
		t.Fatalf("Apply(): %v", err)
	}
	if got := mgr.CustomDefsPath(); got != "/data/clamav/custom" {
		t.Fatalf("CustomDefsPath() = %q", got)
	}
	if got := firstICAPServer(mgr.Current()).Address; got != "127.0.0.1:13440" {
		t.Fatalf("firstICAPServer() = %q", got)
	}
	if got := clamdSocket(mgr.Current()); got != DefaultClamdSocket {
		t.Fatalf("clamdSocket() = %q", got)
	}
	status := mgr.Status()
	if status["enabled"] != true || status["mode"] != "icap" {
		t.Fatalf("unexpected Status(): %+v", status)
	}
	if status["clamav_custom_defs"] != "/data/clamav/custom" {
		t.Fatalf("unexpected custom defs in status: %+v", status)
	}
	if len(emitted) == 0 || emitted[len(emitted)-1] != "service.av.updated" {
		t.Fatalf("expected service.av.updated event, got %v", emitted)
	}

	mgr.customDefsPath = "/tmp/custom-defs"
	if got := mgr.CustomDefsPath(); got != "/tmp/custom-defs" {
		t.Fatalf("CustomDefsPath(custom) = %q", got)
	}

	if err := (*AVManager)(nil).RunFreshclamNow(context.Background()); err == nil {
		t.Fatal("expected nil manager RunFreshclamNow error")
	}
	if err := mgr.RunFreshclamNow(context.Background()); err == nil || !strings.Contains(err.Error(), "clamav mode") {
		t.Fatalf("expected clamav mode error, got %v", err)
	}
	mgr.lastCfg = config.AVConfig{Enabled: false, Mode: "clamav", ClamAV: config.ClamAVConfig{FreshclamEnabled: true}}
	if err := mgr.RunFreshclamNow(context.Background()); err == nil || !strings.Contains(err.Error(), "disabled") {
		t.Fatalf("expected disabled error, got %v", err)
	}
	mgr.lastCfg.Enabled = true
	mgr.freshRunning = true
	if err := mgr.RunFreshclamNow(context.Background()); err == nil || !strings.Contains(err.Error(), "already running") {
		t.Fatalf("expected already running error, got %v", err)
	}

	if got := defaultFreshclamInterval(""); got != 6*time.Hour {
		t.Fatalf("defaultFreshclamInterval(empty) = %s", got)
	}
	if got := defaultFreshclamInterval("90m"); got != 90*time.Minute {
		t.Fatalf("defaultFreshclamInterval(valid) = %s", got)
	}
	if got := defaultFreshclamInterval("invalid"); got != 6*time.Hour {
		t.Fatalf("defaultFreshclamInterval(invalid) = %s", got)
	}
}

func TestAVManagerCacheQueueWorkerAndPolicies(t *testing.T) {
	if res := (*AVManager)(nil).Scan(context.Background(), ScanTask{}); res.Verdict != "unknown" || res.Error == nil {
		t.Fatalf("nil manager Scan() = %+v", res)
	}

	mgr := &AVManager{
		cache:    make(map[string]cachedVerdict),
		maxCache: 1,
		queue:    NewScanQueue(1),
		log:      zap.NewNop().Sugar(),
	}
	mgr.recordVerdict("one", 0, "clean")
	if got, ok := mgr.cachedVerdict("one"); !ok || got != "clean" {
		t.Fatalf("cachedVerdict(one) = %q, %v", got, ok)
	}
	mgr.cache["expired"] = cachedVerdict{verdict: "old", expires: time.Now().Add(-time.Second)}
	if _, ok := mgr.cachedVerdict("expired"); ok {
		t.Fatal("expected expired verdict to be evicted")
	}
	mgr.recordVerdict("two", 0, "clean")
	if _, ok := mgr.cache["one"]; ok {
		t.Fatal("expected cache reset when maxCache reached")
	}

	dropped := make(chan string, 1)
	mgr.OnEvent = func(kind string, attrs map[string]any) {
		if kind == "service.av.queue_dropped" {
			dropped <- kind
		}
	}
	if !mgr.queue.Enqueue(ScanTask{Hash: "queued"}) {
		t.Fatal("expected first queue enqueue to succeed")
	}
	mgr.EnqueueScan(ScanTask{Hash: "overflow"})
	select {
	case <-dropped:
	case <-time.After(time.Second):
		t.Fatal("expected queue_dropped event")
	}

	verdicts := make(chan ScanResult, 1)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	worker := &AVManager{
		queue: NewScanQueue(2),
		log:   zap.NewNop().Sugar(),
		OnVerdict: func(task ScanTask, res ScanResult) {
			verdicts <- res
		},
	}
	worker.StartWorker(ctx)
	worker.EnqueueScan(ScanTask{Hash: "disabled"})
	select {
	case res := <-verdicts:
		if res.Verdict != "disabled" || res.Error != nil {
			t.Fatalf("expected disabled verdict from worker, got %+v", res)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for worker verdict")
	}

	policyMgr := &AVManager{log: zap.NewNop().Sugar(), cache: make(map[string]cachedVerdict), maxCache: 8}
	policyMgr.lastCfg = config.AVConfig{Enabled: true, Mode: "unknown", FailPolicy: "closed", CacheTTL: time.Minute}
	if res := policyMgr.Scan(context.Background(), ScanTask{Hash: "cached"}); res.Verdict != "error" || res.Error == nil {
		t.Fatalf("unknown mode must not scan clean: %+v", res)
	}
	if len(policyMgr.cache) != 0 {
		t.Fatalf("unknown mode cached a verdict: %v", policyMgr.cache)
	}

	policyMgr.lastCfg = config.AVConfig{Enabled: true, Mode: "clamav", FailPolicy: "closed", ClamAV: config.ClamAVConfig{SocketPath: "/nonexistent/clamd.sock"}}
	if res := policyMgr.Scan(context.Background(), ScanTask{Preview: []byte("payload")}); res.Verdict != "error" || res.Error == nil {
		t.Fatalf("expected clamav unavailable error, got %+v", res)
	}

	errBoom := errors.New("boom")
	policyMgr.lastCfg = config.AVConfig{FailPolicy: "open"}
	if res := policyMgr.handleScanError(errBoom, "icap", ScanTask{Hash: "h-open"}); res.Verdict != "bypass" || !errors.Is(res.Error, errBoom) {
		t.Fatalf("expected fail-open bypass, got %+v", res)
	}
	policyMgr.lastCfg = config.AVConfig{FailPolicy: "closed"}
	if res := policyMgr.handleScanError(errBoom, "icap", ScanTask{Hash: "h-closed"}); res.Verdict != "error" || !errors.Is(res.Error, errBoom) {
		t.Fatalf("expected fail-closed error, got %+v", res)
	}
	policyMgr.lastCfg = config.AVConfig{FailPolicy: "closed", FailOpenICS: true}
	if res := policyMgr.handleScanError(errBoom, "icap", ScanTask{Hash: "h-ics", ICS: true}); res.Verdict != "bypass" || !errors.Is(res.Error, errBoom) {
		t.Fatalf("expected ICS fail-open bypass, got %+v", res)
	}
}

func TestAVManagerIcapAndClamAVScanPaths(t *testing.T) {
	icapAddr, _ := startFakeICAP(t, nil, icapReply("ICAP/1.0 200 OK", "X-ICAP-Status: VirusFound", "Encapsulated: null-body=0"))
	clamSock := startFakeClamd(t, nulReply("stream: Eicar-Signature FOUND"))

	var events []string
	mgr := NewAVManager()
	mgr.log = zap.NewNop().Sugar()
	mgr.OnEvent = func(kind string, attrs map[string]any) {
		events = append(events, kind)
	}

	mgr.lastCfg = config.AVConfig{
		Enabled:    true,
		Mode:       "icap",
		FailPolicy: "open",
		ICAP: config.ICAPConfig{
			Servers: []config.ICAPServer{{Address: icapAddr, Service: "avscan"}},
		},
	}
	if res := mgr.Scan(context.Background(), ScanTask{Hash: "icap-hash", Preview: []byte("payload")}); res.Verdict != "malware" || res.Error != nil {
		t.Fatalf("expected ICAP malware verdict, got %+v", res)
	}

	mgr.lastCfg = config.AVConfig{
		Enabled: true,
		Mode:    "clamav",
		ClamAV:  config.ClamAVConfig{SocketPath: clamSock},
	}
	if res := mgr.Scan(context.Background(), ScanTask{Hash: "clam-hash", Preview: []byte("payload")}); res.Verdict != "malware" || res.Signature != "Eicar-Signature" || res.Error != nil {
		t.Fatalf("expected ClamAV malware verdict, got %+v", res)
	}

	foundDetected := false
	for _, kind := range events {
		if kind == "service.av.detected" {
			foundDetected = true
			break
		}
	}
	if !foundDetected {
		t.Fatalf("expected malware detection event, got %v", events)
	}
}

func TestAVManagerHonoursSizeTimeoutAndCacheScope(t *testing.T) {
	var calls atomic.Int32
	clamSock := startFakeClamd(t, func(cmd string, stream []byte) []byte {
		calls.Add(1)
		if string(stream) == "slow" {
			time.Sleep(1500 * time.Millisecond)
		}
		return []byte("stream: OK\x00")
	})
	mgr := &AVManager{log: zap.NewNop().Sugar(), cache: make(map[string]cachedVerdict), maxCache: 8}
	mgr.lastCfg = config.AVConfig{Enabled: true, Mode: "clamav", FailPolicy: "closed", MaxSizeBytes: 4, TimeoutSec: 1, ClamAV: config.ClamAVConfig{SocketPath: clamSock}}

	if res := mgr.Scan(context.Background(), ScanTask{Hash: "big", Preview: []byte("12345")}); res.Verdict != "error" || res.Error == nil {
		t.Fatalf("oversize payload = %+v", res)
	}
	if calls.Load() != 0 {
		t.Fatalf("oversize payload reached clamd")
	}
	start := time.Now()
	if res := mgr.Scan(context.Background(), ScanTask{Hash: "slow", Preview: []byte("slow")}); res.Verdict != "error" {
		t.Fatalf("slow scan = %+v", res)
	}
	if time.Since(start) > 1400*time.Millisecond {
		t.Fatalf("timeoutSec not honoured: %s", time.Since(start))
	}

	// Resetting maxSizeBytes to zero removes the limit.
	mgr.lastCfg.MaxSizeBytes = 0
	mgr.lastCfg.TimeoutSec = 0
	if res := mgr.Scan(context.Background(), ScanTask{Hash: "h", Preview: []byte("12345")}); res.Verdict != "clean" {
		t.Fatalf("unlimited scan = %+v", res)
	}
	before := calls.Load()
	if res := mgr.Scan(context.Background(), ScanTask{Hash: "h", Preview: []byte("12345")}); res.Verdict != "clean" || calls.Load() != before {
		t.Fatalf("cached scan = %+v calls %d->%d", res, before, calls.Load())
	}
	// A new definitions generation or backend must not reuse the verdict.
	mgr.defsGen++
	if mgr.Scan(context.Background(), ScanTask{Hash: "h", Preview: []byte("12345")}); calls.Load() != before+1 {
		t.Fatalf("definitions generation did not invalidate cache")
	}
	other := startFakeClamd(t, nulReply("stream: Other FOUND"))
	mgr.lastCfg.ClamAV.SocketPath = other
	if res := mgr.Scan(context.Background(), ScanTask{Hash: "h", Preview: []byte("12345")}); res.Verdict != "malware" {
		t.Fatalf("backend change reused cached verdict: %+v", res)
	}
}
