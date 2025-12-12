package capture

import (
	"context"
	"fmt"
	"net"
)

// Manager manages interface capture workers (placeholder implementation).
type Manager struct {
	interfaces []string
}

// Config holds capture configuration.
type Config struct {
	Interfaces []string
}

func NewManager(cfg Config) (*Manager, error) {
	// Allow empty capture config for early phases and mgmt-only runs.
	// Capture start will be a no-op in this case.
	if len(cfg.Interfaces) == 0 {
		return &Manager{interfaces: nil}, nil
	}
	return &Manager{interfaces: cfg.Interfaces}, nil
}

// Start begins capture on configured interfaces (placeholder).
func (m *Manager) Start(ctx context.Context) error {
	if len(m.interfaces) == 0 {
		return nil
	}
	// Placeholder: validate interfaces exist locally.
	for _, iface := range m.interfaces {
		if _, err := net.InterfaceByName(iface); err != nil {
			return fmt.Errorf("interface %s not found: %w", iface, err)
		}
	}
	// Future: spawn per-interface capture goroutines.
	return nil
}

// Interfaces returns configured interface names.
func (m *Manager) Interfaces() []string {
	return m.interfaces
}
