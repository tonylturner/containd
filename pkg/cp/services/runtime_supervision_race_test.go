// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

package services

import (
	"context"
	"net"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/tonylturner/containd/pkg/cp/config"
	dpevents "github.com/tonylturner/containd/pkg/dp/events"
	"go.uber.org/zap"
)

func TestSyslogManagerConcurrentFlushAndStatus(t *testing.T) {
	conn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("ListenPacket: %v", err)
	}
	defer conn.Close()

	drainCtx, drainCancel := context.WithCancel(context.Background())
	defer drainCancel()
	go func() {
		buf := make([]byte, 4096)
		for {
			_ = conn.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
			if _, _, err := conn.ReadFrom(buf); err != nil {
				if drainCtx.Err() != nil {
					return
				}
				if nerr, ok := err.(net.Error); ok && nerr.Timeout() {
					continue
				}
				return
			}
		}
	}()

	mgr := NewSyslogManager()
	mgr.log = zap.NewNop().Sugar()

	var nextID atomic.Uint64
	mgr.SetEventLister(func(limit int) []dpevents.Event {
		id := nextID.Add(1)
		return []dpevents.Event{{
			ID:        id,
			Proto:     "modbus",
			Kind:      "service.modbus.read",
			Timestamp: time.Now().UTC(),
			Attributes: map[string]any{
				"count": 1,
			},
		}}
	})
	mgr.mu.Lock()
	mgr.config = config.SyslogConfig{
		Forwarders: []config.SyslogForwarder{{
			Address: "127.0.0.1",
			Port:    conn.LocalAddr().(*net.UDPAddr).Port,
			Proto:   "udp",
		}},
		Format:    "json",
		BatchSize: 8,
	}
	mgr.batchSize = 8
	mgr.flushEvery = 5 * time.Millisecond
	mgr.mu.Unlock()

	testCtx, cancel := context.WithTimeout(context.Background(), 250*time.Millisecond)
	defer cancel()

	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		for testCtx.Err() == nil {
			mgr.flushEvents(testCtx)
		}
	}()
	go func() {
		defer wg.Done()
		for testCtx.Err() == nil {
			_ = mgr.Status()
		}
	}()
	wg.Wait()

	status := mgr.Status()
	if status["sent_total"].(int) == 0 {
		t.Fatalf("expected forwarded syslog packets, got %#v", status)
	}
}

func TestVPNManagerConcurrentLifecycleAndStatus(t *testing.T) {
	dir := t.TempDir()
	openvpnScript := filepath.Join(dir, "openvpn-race.sh")
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

	statusCtx, statusCancel := context.WithTimeout(context.Background(), 400*time.Millisecond)
	defer statusCancel()
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for statusCtx.Err() == nil {
			_ = mgr.Status()
		}
	}()

	for range 3 {
		if err := mgr.Apply(context.Background(), enabled); err != nil {
			t.Fatalf("Apply(enabled): %v", err)
		}
		waitFor(t, 2*time.Second, func() bool {
			mgr.mu.Lock()
			defer mgr.mu.Unlock()
			return mgr.ovpnRunning && mgr.ovpnCmd != nil && mgr.ovpnCmd.Process != nil
		})

		if err := mgr.Apply(context.Background(), config.VPNConfig{}); err != nil {
			t.Fatalf("Apply(disabled): %v", err)
		}
		waitFor(t, 2*time.Second, func() bool {
			mgr.mu.Lock()
			defer mgr.mu.Unlock()
			return !mgr.ovpnRunning && mgr.ovpnCmd == nil
		})
	}

	statusCancel()
	wg.Wait()

	emittedMu.Lock()
	emittedCount := len(emitted)
	emittedMu.Unlock()
	if emittedCount == 0 {
		t.Fatal("expected emitted vpn supervision events")
	}
}
