// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

package services

import (
	"context"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/tonylturner/containd/pkg/cp/config"
	dpevents "github.com/tonylturner/containd/pkg/dp/events"
	"go.uber.org/zap"
)

func waitFor(t *testing.T, timeout time.Duration, check func() bool) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if check() {
			return
		}
		time.Sleep(25 * time.Millisecond)
	}
	t.Fatal("condition not met before timeout")
}

func TestProxyManagerAccessTailers(t *testing.T) {
	dir := t.TempDir()
	logDir := filepath.Join(dir, "logs")
	if err := os.MkdirAll(logDir, 0o755); err != nil {
		t.Fatalf("MkdirAll(logDir): %v", err)
	}
	envoyLog := filepath.Join(logDir, "envoy-access.log")
	nginxLog := filepath.Join(logDir, "nginx-access.log")
	for _, path := range []string{envoyLog, nginxLog} {
		if err := os.WriteFile(path, nil, 0o644); err != nil {
			t.Fatalf("WriteFile(%s): %v", path, err)
		}
	}

	mgr := NewProxyManager(ProxyOptions{BaseDir: filepath.Join(dir, "services"), Supervise: true})
	mgr.log = zap.NewNop().Sugar()
	var mu sync.Mutex
	forwardCount, forwardErrs := 0, 0
	reverseCount, reverseErrs := 0, 0
	// Tail directly for deterministic coverage of the read loop and status parser.
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go mgr.tailAccessLog(ctx, "envoy", envoyLog, func(count int, errs int) {
		mu.Lock()
		defer mu.Unlock()
		forwardCount += count
		forwardErrs += errs
	})
	go mgr.tailAccessLog(ctx, "nginx", nginxLog, func(count int, errs int) {
		mu.Lock()
		defer mu.Unlock()
		reverseCount += count
		reverseErrs += errs
	})
	time.Sleep(300 * time.Millisecond)

	appendLine := func(path string, line string) {
		f, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0o644)
		if err != nil {
			t.Fatalf("OpenFile(%s): %v", path, err)
		}
		if _, err := f.WriteString(line + "\n"); err != nil {
			_ = f.Close()
			t.Fatalf("WriteString(%s): %v", path, err)
		}
		_ = f.Close()
	}

	appendLine(envoyLog, "status=200")
	appendLine(envoyLog, "status=503")
	appendLine(nginxLog, "status=404")

	waitFor(t, 2*time.Second, func() bool {
		mu.Lock()
		defer mu.Unlock()
		return forwardCount >= 2 && forwardErrs >= 1 && reverseCount >= 1 && reverseErrs >= 1
	})

	if got := parseAccessStatus("prefix status=418 suffix"); got != 418 {
		t.Fatalf("parseAccessStatus(valid) = %d", got)
	}
	if got := parseAccessStatus("status=abc"); got != 0 {
		t.Fatalf("parseAccessStatus(invalid) = %d", got)
	}

	mgr.syncAccessTailers(config.ProxyConfig{
		Forward: config.ForwardProxyConfig{Enabled: true, LogRequests: true},
		Reverse: config.ReverseProxyConfig{Enabled: true, Sites: []config.ReverseProxySite{{
			Name:       "example",
			ListenPort: 8443,
			Hostnames:  []string{"example.test"},
			Backends:   []string{"127.0.0.1:8080"},
		}}},
	})
	waitFor(t, time.Second, func() bool {
		mgr.mu.Lock()
		defer mgr.mu.Unlock()
		return mgr.envoyAccessCancel != nil && mgr.nginxAccessCancel != nil
	})
	mgr.syncAccessTailers(config.ProxyConfig{})
	waitFor(t, time.Second, func() bool {
		mgr.mu.Lock()
		defer mgr.mu.Unlock()
		return mgr.envoyAccessCancel == nil && mgr.nginxAccessCancel == nil
	})
}

func TestSyslogManagerForwardLoopAndRun(t *testing.T) {
	conn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("ListenPacket: %v", err)
	}
	defer conn.Close()

	mgr := NewSyslogManager()
	mgr.log = zap.NewNop().Sugar()
	received := make(chan string, 2)
	go func() {
		buf := make([]byte, 4096)
		_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
		n, _, err := conn.ReadFrom(buf)
		if err == nil {
			received <- string(buf[:n])
		}
	}()

	var (
		emittedMu sync.Mutex
		emitted   []string
	)
	mgr.OnEvent = func(kind string, attrs map[string]any) {
		emittedMu.Lock()
		defer emittedMu.Unlock()
		emitted = append(emitted, kind)
	}
	mgr.SetEventLister(func(limit int) []dpevents.Event {
		return []dpevents.Event{{
			ID:        7,
			Proto:     "modbus",
			Kind:      "service.modbus.read",
			Timestamp: time.Date(2026, 3, 13, 12, 0, 0, 0, time.UTC),
			Attributes: map[string]any{
				"count": 1,
			},
		}}
	})

	cfg := config.SyslogConfig{
		Forwarders: []config.SyslogForwarder{{
			Address: "127.0.0.1",
			Port:    conn.LocalAddr().(*net.UDPAddr).Port,
			Proto:   "udp",
		}},
		Format:     "json",
		BatchSize:  10,
		FlushEvery: 1,
	}
	if err := mgr.Apply(context.Background(), cfg); err != nil {
		t.Fatalf("Apply(syslog): %v", err)
	}

	waitFor(t, 2*time.Second, func() bool {
		return mgr.Status()["sent_total"].(int) > 0
	})
	select {
	case payload := <-received:
		if !strings.Contains(payload, `"proto":"modbus"`) {
			t.Fatalf("unexpected syslog payload: %s", payload)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for forwarded syslog packet")
	}
	mgr.mu.Lock()
	lastID := mgr.lastID
	sentTotal := mgr.sentTotal
	mgr.mu.Unlock()
	if lastID != 7 || sentTotal == 0 {
		t.Fatalf("unexpected syslog counters: lastID=%d sentTotal=%d", lastID, sentTotal)
	}
	emittedMu.Lock()
	emittedCount := len(emitted)
	emittedMu.Unlock()
	if emittedCount == 0 {
		t.Fatal("expected emitted syslog events")
	}

	runCtx, cancel := context.WithCancel(context.Background())
	errCh := make(chan error, 1)
	go func() { errCh <- mgr.Run(runCtx) }()
	cancel()
	if err := <-errCh; err == nil {
		t.Fatal("Run() expected context cancellation error")
	}
	mgr.Stop()
}

func TestVPNManagerApplyAndSupervisionLifecycle(t *testing.T) {
	dir := t.TempDir()
	openvpnScript := filepath.Join(dir, "openvpn-test.sh")
	if err := os.WriteFile(openvpnScript, []byte("#!/bin/sh\ntrap 'exit 0' TERM INT\nwhile true; do sleep 1; done\n"), 0o755); err != nil {
		t.Fatalf("WriteFile(openvpnScript): %v", err)
	}
	clientConfig := filepath.Join(dir, "client.ovpn")
	if err := os.WriteFile(clientConfig, []byte("client\nverb 3\n"), 0o600); err != nil {
		t.Fatalf("WriteFile(clientConfig): %v", err)
	}

	var (
		emittedMu sync.Mutex
		emitted   []string
	)
	mgr := &VPNManager{
		BaseDir:          dir,
		SuperviseOpenVPN: true,
		OpenVPNPath:      openvpnScript,
		OnEvent: func(kind string, attrs map[string]any) {
			emittedMu.Lock()
			defer emittedMu.Unlock()
			emitted = append(emitted, kind)
		},
		log: zap.NewNop().Sugar(),
	}

	enabled := config.VPNConfig{
		WireGuard: config.WireGuardConfig{Enabled: true},
		OpenVPN:   config.OpenVPNConfig{Enabled: true, ConfigPath: clientConfig},
	}
	if err := mgr.Apply(context.Background(), enabled); err != nil {
		t.Fatalf("Apply(enabled): %v", err)
	}
	waitFor(t, 2*time.Second, func() bool {
		mgr.mu.Lock()
		defer mgr.mu.Unlock()
		return mgr.ovpnRunning && mgr.ovpnCmd != nil && mgr.ovpnCmd.Process != nil
	})
	vpnJSON := filepath.Join(dir, "vpn.json")
	if _, err := os.Stat(vpnJSON); err != nil {
		t.Fatalf("vpn.json missing: %v", err)
	}

	if err := mgr.Apply(context.Background(), config.VPNConfig{}); err != nil {
		t.Fatalf("Apply(disabled): %v", err)
	}
	waitFor(t, 2*time.Second, func() bool {
		mgr.mu.Lock()
		defer mgr.mu.Unlock()
		return !mgr.ovpnRunning && mgr.ovpnCmd == nil
	})
	if _, err := os.Stat(vpnJSON); !os.IsNotExist(err) {
		t.Fatalf("vpn.json should be removed, stat err=%v", err)
	}
	if err := mgr.stopOpenVPN(); err != nil {
		t.Fatalf("stopOpenVPN(idempotent): %v", err)
	}
	emittedMu.Lock()
	emittedCount := len(emitted)
	emittedMu.Unlock()
	if emittedCount == 0 {
		t.Fatal("expected emitted vpn supervision events")
	}
}
