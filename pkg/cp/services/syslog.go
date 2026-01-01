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

	commonlog "github.com/containd/containd/pkg/common/logging"
	"github.com/containd/containd/pkg/cp/config"
	dpevents "github.com/containd/containd/pkg/dp/events"
	"go.uber.org/zap"
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
	log        *zap.SugaredLogger
	sentTotal  int
	failTotal  int
	lastFlush  time.Time
	lastError  string
	lastBatch  int
	hitLimit   bool
	batchSize  int
	flushEvery time.Duration
}

func NewSyslogManager() *SyslogManager {
	host, _ := os.Hostname()
	return &SyslogManager{
		runCh:    make(chan struct{}),
		stop:     make(chan struct{}),
		hostname: host,
		log:      newSyslogLogger(),
	}
}

func newSyslogLogger() *zap.SugaredLogger {
	lg, err := commonlog.NewZap("syslog", "syslog", commonlog.Options{
		FilePath: "/data/logs/syslog-forwarder.log",
		JSON:     true,
		Level:    "info",
	})
	if err != nil {
		return zap.NewNop().Sugar()
	}
	return lg
}

// Apply updates the in-memory syslog forwarding configuration.
// Future versions should start/stop forwarders accordingly.
func (m *SyslogManager) Apply(ctx context.Context, cfg config.SyslogConfig) error {
	for _, f := range cfg.Forwarders {
		if err := ValidateSyslogForwarder(f); err != nil {
			return err
		}
	}
	format := strings.TrimSpace(cfg.Format)
	if format == "" {
		format = "rfc5424"
	}
	cfg.Format = format
	if cfg.BatchSize <= 0 {
		cfg.BatchSize = 500
	}
	if cfg.BatchSize > 5000 {
		cfg.BatchSize = 5000
	}
	if cfg.FlushEvery <= 0 {
		cfg.FlushEvery = 2
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.config = cfg
	m.batchSize = cfg.BatchSize
	m.flushEvery = time.Duration(cfg.FlushEvery) * time.Second
	if m.OnEvent != nil {
		m.OnEvent("service.syslog.updated", map[string]any{"forwarders": len(cfg.Forwarders), "count": 1})
	}
	m.restartForwarder(ctx)
	m.log.Infow("applied syslog config", "forwarders", len(cfg.Forwarders), "format", cfg.Format)
	return nil
}

func (m *SyslogManager) Current() config.SyslogConfig {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.config
}

// Run keeps the forwarder loop alive for long-running service supervision.
func (m *SyslogManager) Run(ctx context.Context) error {
	if m == nil {
		<-ctx.Done()
		return ctx.Err()
	}
	m.restartForwarder(ctx)
	<-ctx.Done()
	m.Stop()
	return ctx.Err()
}

func (m *SyslogManager) emit(kind string, attrs map[string]any) {
	if m == nil || m.OnEvent == nil {
		return
	}
	m.OnEvent(kind, attrs)
	m.log.Infow("syslog event", "kind", kind, "attrs", attrs)
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
	interval := m.flushEvery
	if interval <= 0 {
		interval = 2 * time.Second
	}
	ticker := time.NewTicker(interval)
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
	batchSize := m.batchSize
	m.mu.Unlock()
	if listFn == nil || len(forwarders) == 0 {
		return
	}
	if batchSize <= 0 {
		batchSize = 500
	}
	evs := listFn(batchSize)
	if len(evs) == 0 {
		return
	}
	hitLimit := len(evs) == batchSize
	// events are newest-first; send oldest-first for readability.
	success := 0
	failures := 0
	var lastErr error
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
			if err := m.sendWithRetry(ctx, network, addr, payload, 3); err != nil {
				failures++
				lastErr = err
				m.log.Errorw("syslog forward failed", "address", addr, "proto", network, "error", err)
				m.emit("service.syslog.forward_failed", map[string]any{"error": err.Error(), "address": addr, "proto": network, "error_count": 1})
			} else {
				success++
			}
		}
		lastID = ev.ID
	}
	m.mu.Lock()
	if lastID > m.lastID {
		m.lastID = lastID
	}
	now := time.Now().UTC()
	m.lastFlush = now
	if lastErr != nil {
		m.lastError = lastErr.Error()
	}
	m.sentTotal += success
	m.failTotal += failures
	m.lastBatch = len(evs)
	m.hitLimit = hitLimit
	m.mu.Unlock()
	if success > 0 {
		m.emit("service.syslog.forward_ok", map[string]any{"count": success})
	}
	if failures > 0 {
		m.emit("service.syslog.forward_failed_batch", map[string]any{"error_count": failures})
	}
}

// Status returns current syslog configuration and counters.
func (m *SyslogManager) Status() map[string]any {
	m.mu.Lock()
	defer m.mu.Unlock()
	var protos []string
	seen := map[string]struct{}{}
	for _, f := range m.config.Forwarders {
		p := strings.ToLower(strings.TrimSpace(f.Proto))
		if p == "" {
			p = "udp"
		}
		if _, ok := seen[p]; !ok {
			seen[p] = struct{}{}
			protos = append(protos, p)
		}
	}
	return map[string]any{
		"configured_forwarders": len(m.config.Forwarders),
		"format":                m.config.Format,
		"protos":                protos,
		"sent_total":            m.sentTotal,
		"failed_total":          m.failTotal,
		"last_flush":            formatTime(m.lastFlush),
		"last_error":            m.lastError,
		"last_batch":            m.lastBatch,
		"batch_limit":           m.batchSize,
		"hit_limit":             m.hitLimit,
		"flush_interval_sec":    int(m.flushEvery.Seconds()),
	}
}

func (m *SyslogManager) sendWithRetry(ctx context.Context, network, addr, payload string, attempts int) error {
	if attempts < 1 {
		attempts = 1
	}
	var lastErr error
	for i := 0; i < attempts; i++ {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		conn, err := net.DialTimeout(network, addr, 2*time.Second)
		if err != nil {
			lastErr = err
		} else {
			_, err = conn.Write(append([]byte(payload), '\n'))
			_ = conn.Close()
			if err == nil {
				return nil
			}
			lastErr = err
		}
		time.Sleep(time.Duration(i+1) * 100 * time.Millisecond)
	}
	return lastErr
}

func formatTime(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.UTC().Format(time.RFC3339Nano)
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

func ValidateSyslogForwarder(f config.SyslogForwarder) error {
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
