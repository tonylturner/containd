package capture

import (
	"context"
	"errors"
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
	if len(cfg.Interfaces) == 0 {
		return nil, errors.New("no interfaces configured for capture")
	}
	return &Manager{interfaces: cfg.Interfaces}, nil
}

// Start begins capture on configured interfaces (placeholder).
func (m *Manager) Start(ctx context.Context) error {
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
