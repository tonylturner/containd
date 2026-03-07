// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

package capture

import (
	"context"
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
	if err := m.Start(context.Background(), func(Packet) {}); err == nil {
		t.Fatalf("expected error for missing interface")
	}
}
