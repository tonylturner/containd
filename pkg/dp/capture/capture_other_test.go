// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

//go:build !linux

package capture

import (
	"context"
	"strings"
	"testing"
)

func TestStartAFPacketRequiresLinux(t *testing.T) {
	mgr, err := NewManager(Config{Interfaces: []string{"lo0"}})
	if err != nil {
		mgr, err = NewManager(Config{Interfaces: []string{"lo"}})
		if err != nil {
			t.Skipf("no loopback interface available: %v", err)
		}
	}

	err = mgr.startAFPacket(context.Background(), func(Packet) {})
	if err != nil {
		t.Fatalf("startAFPacket() returned unexpected error: %v", err)
	}
}

func TestNonLinuxCaptureStubs(t *testing.T) {
	w := &worker{iface: "lo0"}
	if err := w.run(context.Background()); err == nil || !strings.Contains(err.Error(), "only supported on linux") {
		t.Fatalf("worker.run() error = %v, want linux-only error", err)
	}

	mgr := &Manager{}
	if err := mgr.startNFQueue(context.Background(), func(Packet) {}); err == nil || !strings.Contains(err.Error(), "only supported on linux") {
		t.Fatalf("startNFQueue() error = %v, want linux-only error", err)
	}
}
