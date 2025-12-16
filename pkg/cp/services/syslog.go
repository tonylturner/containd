package services

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/containd/containd/pkg/cp/config"
	dpevents "github.com/containd/containd/pkg/dp/events"
)

// SyslogManager applies syslog forwarding configuration and forwards telemetry.
type SyslogManager struct {
	mu         sync.Mutex
	config     config.SyslogConfig
	runCh      chan struct{}
	stop       chan struct{}
	OnEvent    func(kind string, attrs map[string]any)
	listEvents func(limit int) []dpevents.Event
	lastID     uint64
	cancel     context.CancelFunc
	hostname   string
}

func NewSyslogManager() *SyslogManager {
	host, _ := os.Hostname()
	return &SyslogManager{
		runCh:    make(chan struct{}),
		stop:     make(chan struct{}),
		hostname: host,
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
	format := strings.TrimSpace(cfg.Format)
	if format == "" {
		format = "rfc5424"
	}
	cfg.Format = format
	m.mu.Lock()
	defer m.mu.Unlock()
	m.config = cfg
	if m.OnEvent != nil {
		m.OnEvent("service.syslog.updated", map[string]any{"forwarders": len(cfg.Forwarders)})
	}
	m.restartForwarder(ctx)
	return nil
}

func (m *SyslogManager) Current() config.SyslogConfig {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.config
}

// Run is a placeholder for the future forwarding loop.
func (m *SyslogManager) Run(ctx context.Context) error {
	<-ctx.Done()
	return ctx.Err()
}

func (m *SyslogManager) emit(kind string, attrs map[string]any) {
	if m == nil || m.OnEvent == nil {
		return
	}
	m.OnEvent(kind, attrs)
}

// SetEventLister injects a function that returns recent events (newest-first).
func (m *SyslogManager) SetEventLister(fn func(limit int) []dpevents.Event) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.listEvents = fn
}

func (m *SyslogManager) restartForwarder(ctx context.Context) {
	if m.cancel != nil {
		m.cancel()
		m.cancel = nil
	}
	if len(m.config.Forwarders) == 0 || m.listEvents == nil {
		return
	}
	fwdCtx, cancel := context.WithCancel(ctx)
	m.cancel = cancel
	go m.forwardLoop(fwdCtx)
}

func (m *SyslogManager) forwardLoop(ctx context.Context) {
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			m.flushEvents(ctx)
		}
	}
}

func (m *SyslogManager) flushEvents(ctx context.Context) {
	m.mu.Lock()
	listFn := m.listEvents
	lastID := m.lastID
	forwarders := append([]config.SyslogForwarder{}, m.config.Forwarders...)
	m.mu.Unlock()
	if listFn == nil || len(forwarders) == 0 {
		return
	}
	evs := listFn(500)
	if len(evs) == 0 {
		return
	}
	// events are newest-first; send oldest-first for readability.
	for i := len(evs) - 1; i >= 0; i-- {
		ev := evs[i]
		if ev.ID != 0 && ev.ID <= lastID {
			continue
		}
		payload := m.formatEvent(ev, forwarders[0].Proto)
		for _, fwd := range forwarders {
			network := fwd.Proto
			if network == "" {
				network = "udp"
			}
			addr := net.JoinHostPort(fwd.Address, fmt.Sprintf("%d", firstNonZero(fwd.Port, 514)))
			conn, err := net.DialTimeout(network, addr, 2*time.Second)
			if err != nil {
				m.emit("service.syslog.forward_failed", map[string]any{"error": err.Error(), "address": addr, "proto": network})
				continue
			}
			_, err = conn.Write(append([]byte(payload), '\n'))
			_ = conn.Close()
			if err != nil {
				m.emit("service.syslog.forward_failed", map[string]any{"error": err.Error(), "address": addr, "proto": network})
				continue
			}
		}
		lastID = ev.ID
	}
	m.mu.Lock()
	if lastID > m.lastID {
		m.lastID = lastID
	}
	m.mu.Unlock()
}

func (m *SyslogManager) formatEvent(ev dpevents.Event, proto string) string {
	format := m.config.Format
	if format == "" {
		format = "rfc5424"
	}
	if format == "json" {
		b, _ := json.Marshal(ev)
		return string(b)
	}
	return m.formatRFC5424(ev)
}

func (m *SyslogManager) formatRFC5424(ev dpevents.Event) string {
	host := m.hostname
	if strings.TrimSpace(host) == "" {
		host = "containd"
	}
	timestamp := ev.Timestamp.UTC().Format(time.RFC3339Nano)
	sdata := map[string]any{
		"proto": ev.Proto,
		"kind":  ev.Kind,
	}
	for k, v := range ev.Attributes {
		sdata[k] = v
	}
	if ev.SrcIP != "" {
		sdata["src"] = fmt.Sprintf("%s:%d", ev.SrcIP, ev.SrcPort)
	}
	if ev.DstIP != "" {
		sdata["dst"] = fmt.Sprintf("%s:%d", ev.DstIP, ev.DstPort)
	}
	if ev.Transport != "" {
		sdata["transport"] = ev.Transport
	}
	sdJSON, _ := json.Marshal(sdata)
	pri := "<14>" // facility=user(1)*8 + severity=informational(6)
	return fmt.Sprintf("%s1 %s %s containd - - - [containd@47450 %s]", pri, timestamp, host, string(sdJSON))
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
