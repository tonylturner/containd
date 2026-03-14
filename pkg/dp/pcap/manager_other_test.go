// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

//go:build !linux

package pcap

import (
	"context"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/tonylturner/containd/pkg/cp/config"
)

func TestManagerLifecycleOnUnsupportedPlatform(t *testing.T) {
	t.Parallel()

	mgr := NewManager(t.TempDir())
	if err := mgr.Start(context.Background(), config.PCAPConfig{}); err == nil {
		t.Fatal("expected Start to reject empty interface set")
	}
	if err := mgr.Start(context.Background(), config.PCAPConfig{Interfaces: []string{"eth1", "eth1", "eth2"}}); err != nil {
		t.Fatalf("Start: %v", err)
	}
	if err := mgr.Start(context.Background(), config.PCAPConfig{Interfaces: []string{"eth3"}}); err == nil {
		t.Fatal("expected second Start while running to fail")
	}

	deadline := time.Now().Add(2 * time.Second)
	for {
		status := mgr.Status()
		if strings.Contains(status.LastError, "only supported on linux") {
			if len(status.Interfaces) != 2 || status.Interfaces[0] != "eth1" || status.Interfaces[1] != "eth2" {
				t.Fatalf("unexpected status interfaces: %#v", status.Interfaces)
			}
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for stub worker error, current status: %#v", status)
		}
		time.Sleep(10 * time.Millisecond)
	}
	if err := mgr.Stop(); err != nil {
		t.Fatalf("Stop: %v", err)
	}
	if status := mgr.Status(); status.Running {
		t.Fatalf("expected manager to be stopped, got %#v", status)
	}
}

func TestReplayAndWorkerStubs(t *testing.T) {
	t.Parallel()

	if err := replayFile(context.Background(), "/tmp/capture.pcap", &net.Interface{Name: "eth0"}, 100); err == nil {
		t.Fatal("expected replayFile to fail on non-linux")
	}
	w := newWorker("/tmp", "eth0", config.PCAPConfig{})
	if got := w.iface; got != "eth0" {
		t.Fatalf("worker iface = %q", got)
	}
	if err := w.run(context.Background(), NewManager(t.TempDir())); err == nil {
		t.Fatal("expected worker.run to fail on non-linux")
	}
}
