package cli

import (
	"bytes"
	"context"
	"testing"

	"github.com/containd/containd/pkg/cp/config"
)

type memStore struct {
	cfg *config.Config
}

func (m *memStore) Save(ctx context.Context, cfg *config.Config) error {
	m.cfg = cfg
	return nil
}

func (m *memStore) Load(ctx context.Context) (*config.Config, error) {
	if m.cfg == nil {
		return &config.Config{}, nil
	}
	return m.cfg, nil
}

func (m *memStore) Close() error { return nil }

func TestShowVersion(t *testing.T) {
	reg := NewRegistry(&memStore{})
	var buf bytes.Buffer
	if err := reg.Execute(context.Background(), "show version", &buf, nil); err != nil {
		t.Fatalf("execute: %v", err)
	}
	if buf.String() == "" {
		t.Fatalf("expected output")
	}
}

func TestShowZones(t *testing.T) {
	store := &memStore{cfg: &config.Config{Zones: []config.Zone{{Name: "it"}}}}
	reg := NewRegistry(store)
	var buf bytes.Buffer
	if err := reg.Execute(context.Background(), "show zones", &buf, nil); err != nil {
		t.Fatalf("execute: %v", err)
	}
	if got := buf.String(); got == "" || got != "it\n" {
		t.Fatalf("unexpected output: %q", got)
	}
}

func TestUnknownCommand(t *testing.T) {
	reg := NewRegistry(&memStore{})
	err := reg.Execute(context.Background(), "does not exist", nil, nil)
	if err == nil {
		t.Fatalf("expected error for unknown command")
	}
}
