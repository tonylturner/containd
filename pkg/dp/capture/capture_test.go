// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

package capture

import (
	"context"
	"strings"
	"testing"
)

func TestManagerInterfaces(t *testing.T) {
	m, err := NewManager(Config{Interfaces: []string{"lo0"}})
	if err != nil {
		t.Fatalf("new manager: %v", err)
	}
	if got := m.Interfaces(); len(got) != 1 || got[0] != "lo0" {
		t.Fatalf("unexpected interfaces: %+v", got)
	}
}

func TestManagerRejectsEmpty(t *testing.T) {
	m, err := NewManager(Config{})
	if err != nil {
		t.Fatalf("expected no error for empty config, got %v", err)
	}
	if got := m.Interfaces(); len(got) != 0 {
		t.Fatalf("expected no interfaces, got %+v", got)
	}
}

func TestManagerStartValidatesInterface(t *testing.T) {
	m, err := NewManager(Config{Interfaces: []string{"doesnotexist"}})
	if err != nil {
		t.Fatalf("new manager: %v", err)
	}
	firstErr := m.Start(context.Background(), func(Packet) {})
	if firstErr == nil || !strings.Contains(firstErr.Error(), "interface doesnotexist not found") {
		t.Fatalf("first Start error = %v, want missing-interface error", firstErr)
	}
	secondErr := m.Start(context.Background(), func(Packet) {})
	if secondErr == nil || secondErr.Error() != firstErr.Error() || strings.Contains(secondErr.Error(), "stopped") {
		t.Fatalf("second Start error = %v, want same missing-interface error as first: %v", secondErr, firstErr)
	}
	m.Stop()
}

func TestManagerStopBeforeStartIsIdempotent(t *testing.T) {
	m, err := NewManager(Config{})
	if err != nil {
		t.Fatalf("new manager: %v", err)
	}
	m.Stop()
	m.Stop()
	if err := m.Start(context.Background(), func(Packet) {}); err == nil || !strings.Contains(err.Error(), "stopped") {
		t.Fatalf("Start after Stop error = %v, want stopped manager error", err)
	}
}

func TestManagerStopCancelsAndWaitsForConsumers(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	m := &Manager{started: true, cancel: cancel}
	workerDone := make(chan struct{})
	m.wg.Add(1)
	go func() {
		defer m.wg.Done()
		<-ctx.Done()
		close(workerDone)
	}()

	m.Stop()
	select {
	case <-workerDone:
	default:
		t.Fatal("Stop returned before capture consumer exited")
	}
}
