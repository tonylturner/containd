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
	if _, err := NewManager(Config{}); err == nil {
		t.Fatalf("expected error for empty config")
	}
}

func TestManagerStartValidatesInterface(t *testing.T) {
	m, err := NewManager(Config{Interfaces: []string{"doesnotexist"}})
	if err != nil {
		t.Fatalf("new manager: %v", err)
	}
	if err := m.Start(context.Background()); err == nil {
		t.Fatalf("expected error for missing interface")
	}
}
