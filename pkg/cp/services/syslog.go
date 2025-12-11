package services

import (
	"context"
	"fmt"
	"net"
	"sync"

	"github.com/containd/containd/pkg/cp/config"
)

// SyslogManager applies syslog forwarding configuration.
// This is a placeholder for future forwarding implementation.
type SyslogManager struct {
	mu     sync.Mutex
	config config.SyslogConfig
	runCh  chan struct{}
	stop   chan struct{}
}

func NewSyslogManager() *SyslogManager {
	return &SyslogManager{
		runCh: make(chan struct{}),
		stop:  make(chan struct{}),
	}
}

// Apply updates the in-memory syslog forwarding configuration.
// Future versions should start/stop forwarders accordingly.
func (m *SyslogManager) Apply(ctx context.Context, cfg config.SyslogConfig) error {
	for _, f := range cfg.Forwarders {
		if err := validateForwarder(f); err != nil {
			return err
		}
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.config = cfg
	// In a real implementation we'd restart forwarders here.
	return nil
}

func (m *SyslogManager) Current() config.SyslogConfig {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.config
}

// Run is a placeholder for the future forwarding loop.
func (m *SyslogManager) Run(ctx context.Context) error {
	// Placeholder loop: waits for stop signal or context cancel.
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-m.stop:
		return nil
	}
}

// Stop stops the manager loop.
func (m *SyslogManager) Stop() {
	select {
	case m.stop <- struct{}{}:
	default:
	}
}

func validateForwarder(f config.SyslogForwarder) error {
	if f.Address == "" {
		return fmt.Errorf("syslog forwarder address required")
	}
	if f.Port <= 0 || f.Port > 65535 {
		return fmt.Errorf("syslog forwarder %s invalid port %d", f.Address, f.Port)
	}
	if f.Proto != "" && f.Proto != "udp" && f.Proto != "tcp" {
		return fmt.Errorf("syslog forwarder %s invalid proto %s", f.Address, f.Proto)
	}
	if net.ParseIP(f.Address) == nil {
		// Allow hostnames but keep a basic check.
		if len(f.Address) > 253 {
			return fmt.Errorf("syslog forwarder address too long")
		}
	}
	return nil
}
