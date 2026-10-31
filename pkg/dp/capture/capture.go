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

// TCPFlags are the eight TCP header flag bits.
type TCPFlags uint8

const (
	TCPFlagFIN TCPFlags = 0x01
	TCPFlagSYN TCPFlags = 0x02
	TCPFlagRST TCPFlags = 0x04
	TCPFlagPSH TCPFlags = 0x08
	TCPFlagACK TCPFlags = 0x10
	TCPFlagURG TCPFlags = 0x20
	TCPFlagECE TCPFlags = 0x40
	TCPFlagCWR TCPFlags = 0x80
)

// TCPMeta carries the decoded TCP header fields.
type TCPMeta struct {
	Valid  bool // header decoded; Seq 0 is a real value
	Seq    uint32
	Ack    uint32
	Flags  TCPFlags
	Window uint16
}

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
	Payload   []byte // L4 payload; always an owned copy
	TCP       TCPMeta
	Token     Token  // zero unless delivered inline
	Mark      uint32 // NFQUEUE skb mark when HasMark; opaque to capture
	HasMark   bool
	// Queue is nil on observational sources. Missing queue/conntrack fields
	// stay missing; a reverse tuple is never synthesized from packet headers.
	Queue             *QueueMetadata
	publicationPinned bool
	// Invalid is "" when the packet decoded. Otherwise it names the reason
	// (see the Invalid* constants); tuple fields are then best effort.
	Invalid string
}

// Manager manages interface capture workers.
type Manager struct {
	interfaces []string
	cfg        Config

	settler *settler
	comp    *completer // inline completions; NFQUEUE only, from Start to Stop

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
	// OnVerdict and OnSource report inline verdict completions and source
	// state. They run on one capture-owned completion goroutine, in
	// submission order; Stop returns after the last one.
	OnVerdict VerdictFunc
	OnSource  func(SourceEvent)
	// PublicationFence pins policy through handler evaluation and the actual
	// verdict submission. Configure before Start, never while capture runs.
	// A handler resolves earlier tokens with Decision.Resolved, not Settle:
	// submitting an earlier deferred token would recursively acquire the pin.
	PublicationFence *sync.RWMutex
}

// PublicationPinned reports capture's ownership of the publication read lock.
func (p Packet) PublicationPinned() bool { return p.publicationPinned }

// SetPublicationFence binds an unstarted manager to its engine's publication.
func (m *Manager) SetPublicationFence(fence *sync.RWMutex) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.started {
		panic("capture: publication fence changed after start")
	}
	m.cfg.PublicationFence = fence
}

// RetireFlushed retires tokens dropped by a successful policy-table replacement.
// The caller owns the publication write lock. No verdict is sent and no source
// transition occurs; completions report known loss, never delivery.
func (m *Manager) RetireFlushed() {
	if g := m.settler.current(); g != nil {
		g.retireFlushed()
	}
}

func NewManager(cfg Config) (*Manager, error) {
	cfg = normalizeConfig(cfg)
	settler := &settler{inline: strings.EqualFold(cfg.Mode, "nfqueue")}
	// Allow empty capture config for early phases and mgmt-only runs.
	// Capture start will be a no-op in this case. NFQUEUE mode does not
	// need interface names (packets arrive via the kernel queue, not an
	// eth listener) — only the QueueID matters.
	if len(cfg.Interfaces) == 0 && !strings.EqualFold(cfg.Mode, "nfqueue") {
		return &Manager{interfaces: nil, cfg: cfg, settler: settler}, nil
	}
	return &Manager{interfaces: cfg.Interfaces, cfg: cfg, settler: settler}, nil
}

// Start begins capture on configured interfaces after validating they exist.
// In NFQUEUE mode it returns nil only after the queue is bound; a failed
// first bind is returned, not retried. A failed Start leaves the manager
// retryable; no consumer goroutines remain when Start returns an error.
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
		m.comp = newCompleter(m.cfg.OnVerdict, m.cfg.OnSource)
		err = m.startNFQueue(runCtx, handler)
	}
	if err != nil {
		m.started = false
		m.cancel = nil
		comp := m.comp
		m.comp = nil
		m.mu.Unlock()
		cancel()
		m.wg.Wait()
		if comp != nil {
			comp.close()
		}
		return err
	}
	m.mu.Unlock()
	return nil
}

// Stop permanently stops the manager, cancels capture, waits for all
// consumer goroutines to exit, and then delivers every pending OnVerdict and
// OnSource completion. It is safe to call repeatedly, including before Start
// or after a failed Start.
func (m *Manager) Stop() {
	m.mu.Lock()
	m.stopped = true
	cancel := m.cancel
	m.cancel = nil
	comp := m.comp
	m.comp = nil
	m.mu.Unlock()
	if cancel != nil {
		cancel()
	}
	m.wg.Wait()
	if comp != nil {
		comp.close()
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
