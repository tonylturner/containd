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
	"sync/atomic"
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
	started    atomic.Bool
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
	// Capture start will be a no-op in this case.
	if len(cfg.Interfaces) == 0 {
		return &Manager{interfaces: nil, cfg: cfg}, nil
	}
	return &Manager{interfaces: cfg.Interfaces, cfg: cfg}, nil
}

// Start begins capture on configured interfaces after validating they exist.
func (m *Manager) Start(ctx context.Context, handler Handler) error {
	if len(m.interfaces) == 0 {
		return nil
	}
	if handler == nil {
		return errors.New("capture handler is required")
	}
	if m.started.Swap(true) {
		return nil
	}
	// Placeholder: validate interfaces exist locally.
	for _, iface := range m.interfaces {
		if _, err := net.InterfaceByName(iface); err != nil {
			return fmt.Errorf("interface %s not found: %w", iface, err)
		}
	}
	switch strings.ToLower(m.cfg.Mode) {
	case "", "afpacket":
		return m.startAFPacket(ctx, handler)
	case "nfqueue":
		return errors.New("nfqueue capture is not implemented yet")
	default:
		return fmt.Errorf("unsupported capture mode %q", m.cfg.Mode)
	}
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
	var wg sync.WaitGroup
	for _, iface := range m.interfaces {
		w := &worker{iface: iface, cfg: m.cfg, handler: handler}
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := w.run(ctx); err != nil {
				if m.cfg.OnError != nil {
					m.cfg.OnError(err)
				}
			}
		}()
	}
	go func() {
		wg.Wait()
	}()
	return nil
}

// Interfaces returns configured interface names.
func (m *Manager) Interfaces() []string {
	return m.interfaces
}
