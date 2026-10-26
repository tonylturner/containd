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

// newTestAVManager returns a manager with test paths, stopped at cleanup.
func newTestAVManager(t *testing.T, opts AVOptions) *AVManager {
	t.Helper()
	if opts.StateDir == "" {
		opts.StateDir = t.TempDir()
	}
	if opts.DatabaseDir == "" {
		opts.DatabaseDir = t.TempDir()
	}
	m := NewAVManager(context.Background(), opts)
	m.log = zap.NewNop().Sugar()
	t.Cleanup(func() {
		if err := m.Stop(); err != nil {
			t.Errorf("Stop: %v", err)
		}
	})
	return m
}

func TestAVManagerICAPApplyStatusAndFreshclamGuards(t *testing.T) {
	icapAddr, _ := startFakeICAP(t, nil, icapReply("ICAP/1.0 200 OK", "Methods: RESPMOD", "Encapsulated: null-body=0"))
	mgr := newTestAVManager(t, AVOptions{})
	var mu atomic.Value
	mgr.OnEvent = func(kind string, attrs map[string]any) { mu.Store(kind) }

	cfg := config.AVConfig{
		Enabled: true,
		Mode:    "icap",
		ICAP:    config.ICAPConfig{Servers: []config.ICAPServer{{Address: icapAddr, Service: "avscan"}}},
	}
	if err := mgr.Apply(context.Background(), cfg); err != nil {
		t.Fatalf("Apply(): %v", err)
	}
	if mu.Load() != "service.av.updated" {
		t.Fatalf("last event = %v, want service.av.updated", mu.Load())
	}
	status := mgr.Status(context.Background())
	if status["enabled"] != true || status["mode"] != "icap" || status["ready"] != true || status["clamav_custom_defs"] != DefaultCustomDefsPath {
		t.Fatalf("unexpected Status(): %+v", status)
	}
	if status["timeout"] != 5 || status["cache_ttl"] != "10m0s" {
		t.Fatalf("effective defaults not reported: %+v", status)
	}

	// An unreachable ICAP server fails the apply instead of being recorded only.
	cfg.ICAP.Servers[0].Address = "127.0.0.1:1"
	if err := mgr.Apply(context.Background(), cfg); err == nil {
		t.Fatal("Apply accepted an unreachable ICAP server")
	}
	if status := mgr.Status(context.Background()); status["ready"] != false || status["last_error"] == "" {
		t.Fatalf("unreachable server reported ready: %+v", status)
	}

	if err := (*AVManager)(nil).RunFreshclamNow(); err == nil {
		t.Fatal("expected nil manager RunFreshclamNow error")
	}
	if err := mgr.RunFreshclamNow(); !errors.Is(err, ErrAVConflict) || !strings.Contains(err.Error(), "clamav mode") {
		t.Fatalf("expected clamav mode conflict, got %v", err)
	}
	if err := mgr.Apply(context.Background(), config.AVConfig{Mode: "bogus", Enabled: true}); !errors.Is(err, ErrAVInvalid) {
		t.Fatalf("unknown mode = %v, want ErrAVInvalid", err)
	}

	for in, want := range map[string]time.Duration{"": 6 * time.Hour, "90m": 90 * time.Minute, "invalid": 6 * time.Hour} {
		if got := freshclamInterval(in); got != want {
			t.Fatalf("freshclamInterval(%q) = %s, want %s", in, got, want)
		}
	}
	if _, err := parseFreshclamSchedule("0 */4 * * *"); !errors.Is(err, ErrAVInvalid) {
		t.Fatalf("cron schedule accepted: %v", err)
	}
}

func TestAVManagerCacheQueueWorkerAndPolicies(t *testing.T) {
	if res := (*AVManager)(nil).Scan(context.Background(), ScanTask{}); res.Verdict != "unknown" || res.Error == nil {
		t.Fatalf("nil manager Scan() = %+v", res)
	}

	mgr := newTestAVManager(t, AVOptions{})
	mgr.maxCache = 1
	mgr.queue = NewScanQueue(1)
	mgr.recordVerdict("one", time.Minute, "clean")
	if got, ok := mgr.cachedVerdict("one"); !ok || got != "clean" {
		t.Fatalf("cachedVerdict(one) = %q, %v", got, ok)
	}
	mgr.cache["expired"] = cachedVerdict{verdict: "old", expires: time.Now().Add(-time.Second)}
	if _, ok := mgr.cachedVerdict("expired"); ok {
		t.Fatal("expected expired verdict to be evicted")
	}
	mgr.recordVerdict("two", time.Minute, "clean")
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
	worker := newTestAVManager(t, AVOptions{})
	worker.OnVerdict = func(task ScanTask, res ScanResult) { verdicts <- res }
	worker.StartWorker()
	worker.EnqueueScan(ScanTask{Hash: "disabled"})
	select {
	case res := <-verdicts:
		if res.Verdict != "disabled" || res.Error != nil {
			t.Fatalf("expected disabled verdict from worker, got %+v", res)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for worker verdict")
	}

	policyMgr := newTestAVManager(t, AVOptions{})
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
	for _, tc := range []struct {
		cfg     config.AVConfig
		ics     bool
		verdict string
	}{
		{cfg: config.AVConfig{FailPolicy: "open"}, verdict: "bypass"},
		{cfg: config.AVConfig{}, verdict: "bypass"},
		{cfg: config.AVConfig{FailPolicy: "closed"}, verdict: "error"},
		{cfg: config.AVConfig{FailPolicy: "closed", FailOpenICS: true}, ics: true, verdict: "bypass"},
		{cfg: config.AVConfig{FailPolicy: "closed"}, ics: true, verdict: "error"},
	} {
		if res := policyMgr.handleScanError(tc.cfg, errBoom, "icap", ScanTask{Hash: "h", ICS: tc.ics}); res.Verdict != tc.verdict || !errors.Is(res.Error, errBoom) {
			t.Fatalf("handleScanError(%+v, ics=%v) = %+v, want %s", tc.cfg, tc.ics, res, tc.verdict)
		}
	}
	if status := policyMgr.Status(context.Background()); status["errors_count"] == 0 {
		t.Fatalf("scan errors not counted: %+v", status)
	}
}

func TestAVManagerIcapAndClamAVScanPaths(t *testing.T) {
	icapAddr, _ := startFakeICAP(t, nil, icapReply("ICAP/1.0 200 OK", "X-ICAP-Status: VirusFound", "Encapsulated: null-body=0"))
	clamSock := startFakeClamd(t, nulReply("stream: Eicar-Signature FOUND"))

	mgr := newTestAVManager(t, AVOptions{})
	mgr.lastCfg = config.AVConfig{
		Enabled:    true,
		Mode:       "icap",
		FailPolicy: "open",
		ICAP:       config.ICAPConfig{Servers: []config.ICAPServer{{Address: icapAddr, Service: "avscan"}}},
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
	if status := mgr.Status(context.Background()); status["detections"] != 2 || status["count"] != 2 {
		t.Fatalf("scan counters = %+v", status)
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
	mgr := newTestAVManager(t, AVOptions{})
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

	// Resetting maxSizeBytes and timeoutSec to zero restores the defaults.
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
