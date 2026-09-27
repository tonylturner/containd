// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

package capture

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"
)

// Handler receives decoded capture packets.
type Handler func(pkt Packet)

// Packet is a minimal decoded packet for DPI/telemetry.
type Packet struct {
	Timestamp time.Time
	Interface string
	SrcIP     net.IP
	DstIP     net.IP
	SrcPort   uint16
	DstPort   uint16
	Proto     uint8  // IP protocol number (6 TCP, 17 UDP)
	Transport string // "tcp" or "udp"
	Payload   []byte // L4 payload
}

// Manager manages interface capture workers.
type Manager struct {
	interfaces []string
	cfg        Config

	mu      sync.Mutex
	started bool
	stopped bool
	cancel  context.CancelFunc
	wg      sync.WaitGroup
}

// Config holds capture configuration.
type Config struct {
	Interfaces []string
	Mode       string
	QueueID    int
	Snaplen    int
	BufferMB   int
	Promisc    bool
	OnError    func(error)
}

func NewManager(cfg Config) (*Manager, error) {
	cfg = normalizeConfig(cfg)
	// Allow empty capture config for early phases and mgmt-only runs.
	// Capture start will be a no-op in this case. NFQUEUE mode does not
	// need interface names (packets arrive via the kernel queue, not an
	// eth listener) — only the QueueID matters.
	if len(cfg.Interfaces) == 0 && !strings.EqualFold(cfg.Mode, "nfqueue") {
		return &Manager{interfaces: nil, cfg: cfg}, nil
	}
	return &Manager{interfaces: cfg.Interfaces, cfg: cfg}, nil
}

// Start begins capture on configured interfaces after validating they exist.
func (m *Manager) Start(ctx context.Context, handler Handler) error {
	m.mu.Lock()
	if m.stopped {
		m.mu.Unlock()
		return errors.New("capture manager is stopped")
	}
	if m.started {
		m.mu.Unlock()
		return nil
	}
	mode := strings.ToLower(m.cfg.Mode)
	if len(m.interfaces) == 0 && mode != "nfqueue" {
		m.started = true
		m.mu.Unlock()
		return nil
	}
	if handler == nil {
		m.mu.Unlock()
		return errors.New("capture handler is required")
	}
	// Validate AFPACKET-style interfaces exist locally. NFQUEUE mode
	// skips this — it has no interface dependency.
	if mode != "nfqueue" {
		for _, iface := range m.interfaces {
			if _, err := net.InterfaceByName(iface); err != nil {
				m.mu.Unlock()
				return fmt.Errorf("interface %s not found: %w", iface, err)
			}
		}
	}
	if mode != "" && mode != "afpacket" && mode != "nfqueue" {
		m.mu.Unlock()
		return fmt.Errorf("unsupported capture mode %q", m.cfg.Mode)
	}
	runCtx, cancel := context.WithCancel(ctx)
	m.started = true
	m.cancel = cancel
	var err error
	switch mode {
	case "", "afpacket":
		err = m.startAFPacket(runCtx, handler)
	case "nfqueue":
		err = m.startNFQueue(runCtx, handler)
	}
	if err != nil {
		m.started = false
		m.stopped = true
		m.cancel = nil
		m.mu.Unlock()
		cancel()
		m.wg.Wait()
		return err
	}
	m.mu.Unlock()
	return nil
}

// Stop cancels capture and waits for all consumer goroutines to exit.
// It is safe to call repeatedly, including before Start.
func (m *Manager) Stop() {
	m.mu.Lock()
	m.stopped = true
	cancel := m.cancel
	m.cancel = nil
	m.mu.Unlock()
	if cancel != nil {
		cancel()
	}
	m.wg.Wait()
}

func normalizeConfig(cfg Config) Config {
	if cfg.Snaplen <= 0 {
		cfg.Snaplen = 2048
	}
	if cfg.Mode == "" {
		cfg.Mode = "afpacket"
	}
	return cfg
}

func (m *Manager) startAFPacket(ctx context.Context, handler Handler) error {
	for _, iface := range m.interfaces {
		w := &worker{iface: iface, cfg: m.cfg, handler: handler}
		m.wg.Add(1)
		go func() {
			defer m.wg.Done()
			if err := w.run(ctx); err != nil {
				if m.cfg.OnError != nil {
					m.cfg.OnError(err)
				}
			}
		}()
	}
	return nil
}

// Interfaces returns configured interface names.
func (m *Manager) Interfaces() []string {
	return m.interfaces
}
