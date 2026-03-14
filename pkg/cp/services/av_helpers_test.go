// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

package services

import (
	"bytes"
	"context"
	"errors"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/tonylturner/containd/pkg/cp/config"
	"go.uber.org/zap"
)

func startICAPTestServer(t *testing.T, statusLine string, headers ...string) string {
	t.Helper()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				_ = c.SetDeadline(time.Now().Add(2 * time.Second))
				buf := make([]byte, 4096)
				_, _ = c.Read(buf)
				var b strings.Builder
				b.WriteString(statusLine)
				b.WriteString("\r\n")
				for _, h := range headers {
					b.WriteString(h)
					b.WriteString("\r\n")
				}
				b.WriteString("\r\n")
				_, _ = c.Write([]byte(b.String()))
			}(conn)
		}
	}()

	return ln.Addr().String()
}

func startClamAVTestSocket(t *testing.T, response string) string {
	t.Helper()

	dir, err := os.MkdirTemp("/tmp", "clamav-")
	if err != nil {
		t.Fatalf("MkdirTemp: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	socketPath := filepath.Join(dir, "clamd.sock")
	ln, err := net.Listen("unix", socketPath)
	if err != nil {
		t.Fatalf("Listen(unix): %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				_ = c.SetDeadline(time.Now().Add(2 * time.Second))
				buf := make([]byte, 4096)
				var payload []byte
				for {
					n, err := c.Read(buf)
					if n > 0 {
						payload = append(payload, buf[:n]...)
						if bytes.Contains(payload, []byte{0, 0, 0, 0}) {
							break
						}
					}
					if err != nil {
						return
					}
				}
				_, _ = c.Write([]byte(response + "\n"))
			}(conn)
		}
	}()

	return socketPath
}

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
	if mgr.icap.MaxSize != 2048 {
		t.Fatalf("expected ICAP max size 2048, got %d", mgr.icap.MaxSize)
	}
	if got := mgr.CustomDefsPath(); got != "/data/clamav/custom" {
		t.Fatalf("CustomDefsPath() = %q", got)
	}
	if got := mgr.pickICAPServer().Address; got != "127.0.0.1:13440" {
		t.Fatalf("pickICAPServer() = %q", got)
	}
	if got := mgr.pickClamSocket(); got != "/var/run/clamav/clamd.ctl" {
		t.Fatalf("pickClamSocket() = %q", got)
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
	mgr.recordVerdict("one", "clean")
	if got, ok := mgr.cachedVerdict("one"); !ok || got != "clean" {
		t.Fatalf("cachedVerdict(one) = %q, %v", got, ok)
	}
	mgr.cache["expired"] = cachedVerdict{verdict: "old", expires: time.Now().Add(-time.Second)}
	if _, ok := mgr.cachedVerdict("expired"); ok {
		t.Fatal("expected expired verdict to be evicted")
	}
	mgr.recordVerdict("two", "clean")
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

	policyMgr := &AVManager{log: zap.NewNop().Sugar()}
	policyMgr.lastCfg = config.AVConfig{Enabled: true, Mode: "unknown", CacheTTL: time.Minute}
	if res := policyMgr.Scan(context.Background(), ScanTask{Hash: "cached"}); res.Verdict != "clean" || res.Error != nil {
		t.Fatalf("unexpected Scan() result for unknown mode: %+v", res)
	}
	if got, ok := policyMgr.cachedVerdict("cached"); !ok || got != "clean" {
		t.Fatalf("expected cached clean verdict, got %q, %v", got, ok)
	}

	policyMgr.lastCfg = config.AVConfig{Enabled: true, Mode: "clamav"}
	policyMgr.clamd = nil
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

func TestICAPAndClamAVClients(t *testing.T) {
	t.Run("icap probe and scan", func(t *testing.T) {
		cleanAddr := startICAPTestServer(t, "ICAP/1.0 200 OK")
		icap := &ICAPClient{Timeout: time.Second, MaxSize: 8}
		srv := config.ICAPServer{Address: cleanAddr, Service: "avscan"}
		if err := icap.Probe(context.Background(), srv); err != nil {
			t.Fatalf("Probe(clean): %v", err)
		}
		if verdict, err := icap.Scan(context.Background(), srv, []byte("ok")); err != nil || verdict != "clean" {
			t.Fatalf("Scan(clean) = %q, %v", verdict, err)
		}
		if verdict, err := icap.Scan(context.Background(), srv, []byte("too-large")); err == nil || verdict != "skipped" {
			t.Fatalf("Scan(too-large) = %q, %v", verdict, err)
		}

		malwareAddr := startICAPTestServer(t, "ICAP/1.0 200 OK", "X-ICAP-Status: VirusFound")
		if verdict, err := (&ICAPClient{Timeout: time.Second}).Scan(context.Background(), config.ICAPServer{Address: malwareAddr}, []byte("evil")); err != nil || verdict != "malware" {
			t.Fatalf("Scan(malware) = %q, %v", verdict, err)
		}
	})

	t.Run("clamav client scan", func(t *testing.T) {
		cleanSock := startClamAVTestSocket(t, "stream: OK")
		client := &ClamAVClient{Timeout: time.Second, Socket: cleanSock}
		if verdict, err := client.Scan(context.Background(), []byte("clean")); err != nil || verdict != "clean" {
			t.Fatalf("ClamAV clean = %q, %v", verdict, err)
		}

		malwareSock := startClamAVTestSocket(t, "stream: Eicar FOUND")
		client.Socket = malwareSock
		if verdict, err := client.Scan(context.Background(), []byte("malware")); err != nil || verdict != "malware" {
			t.Fatalf("ClamAV malware = %q, %v", verdict, err)
		}

		errorSock := startClamAVTestSocket(t, "stream: ERROR something bad")
		client.Socket = errorSock
		if verdict, err := client.Scan(context.Background(), []byte("broken")); err == nil || verdict != "error" {
			t.Fatalf("ClamAV error = %q, %v", verdict, err)
		}
	})
}

func TestAVManagerIcapAndClamAVScanPaths(t *testing.T) {
	icapAddr := startICAPTestServer(t, "ICAP/1.0 200 OK", "X-ICAP-Status: VirusFound")
	clamSock := startClamAVTestSocket(t, "stream: Eicar FOUND")

	var events []string
	mgr := NewAVManager()
	mgr.log = zap.NewNop().Sugar()
	mgr.OnEvent = func(kind string, attrs map[string]any) {
		events = append(events, kind)
	}
	mgr.icap = &ICAPClient{Timeout: time.Second}
	mgr.clamd = &ClamAVClient{Timeout: time.Second, Socket: clamSock}
	mgr.clamdSocket = clamSock

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
	if res := mgr.Scan(context.Background(), ScanTask{Hash: "clam-hash", Preview: []byte("payload")}); res.Verdict != "malware" || res.Error != nil {
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

	dir := t.TempDir()
	mgr.customDefsPath = filepath.Join(dir, "defs")
	if err := os.MkdirAll(mgr.customDefsPath, 0o755); err != nil {
		t.Fatalf("MkdirAll(customDefsPath): %v", err)
	}
	if got := mgr.CustomDefsPath(); got == "" {
		t.Fatal("expected non-empty custom defs path")
	}
}
