// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

package services

import (
	"context"
	"encoding/json"
	"fmt"
	"maps"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/tonylturner/containd/pkg/common/evidence"
	commonlog "github.com/tonylturner/containd/pkg/common/logging"
	"github.com/tonylturner/containd/pkg/cp/audit"
	"github.com/tonylturner/containd/pkg/cp/config"
	dpevents "github.com/tonylturner/containd/pkg/dp/events"
	"go.uber.org/zap"
)

// SyslogManager applies syslog forwarding configuration and forwards telemetry.
type SyslogManager struct {
	controlMu  sync.Mutex // lifecycle operations; never held by workers
	eventMu    sync.Mutex // serializes manual and scheduled event flushes
	mu         sync.Mutex
	config     config.SyslogConfig
	applied    bool // config holds an applied configuration
	OnEvent    func(kind string, attrs map[string]any)
	feeds      map[evidence.Source]dpevents.FeedReader
	progress   map[string]map[evidence.Source]eventProgress
	done       chan struct{}
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

	// Audit forwarding. Lifecycle operations join scheduled workers, then
	// lock eventMu/auditMu before mu. Per-stream gates serialize delivery
	// without coupling different destinations or sources.
	auditMu         sync.Mutex
	auditLog        audit.ForwardLog
	auditForwarders map[string]auditForwarderStatus
	auditGates      map[string]*sync.Mutex
	auditSentTotal  int
	auditFailTotal  int
	auditLastError  string
	auditLastFlush  time.Time
}

func NewSyslogManager() *SyslogManager {
	host, _ := os.Hostname()
	return &SyslogManager{
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

// Apply updates the syslog forwarding configuration and restarts the forwarder
// loop. The loop outlives ctx, which may belong to the request that applied
// the configuration; Stop ends it.
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
	m.controlMu.Lock()
	defer m.controlMu.Unlock()
	m.stopAndWait()
	m.eventMu.Lock()
	defer m.eventMu.Unlock()
	m.auditMu.Lock()
	defer m.auditMu.Unlock()
	m.mu.Lock()
	defer m.mu.Unlock()
	m.config = cfg
	m.applied = true
	m.batchSize = cfg.BatchSize
	m.flushEvery = time.Duration(cfg.FlushEvery) * time.Second
	if m.OnEvent != nil {
		m.OnEvent("service.syslog.updated", map[string]any{"forwarders": len(cfg.Forwarders), "count": 1})
	}
	m.syncEventTargets()
	m.syncAuditCursors()
	m.restartForwarder()
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
	m.controlMu.Lock()
	m.mu.Lock()
	m.restartForwarder()
	m.mu.Unlock()
	m.controlMu.Unlock()
	<-ctx.Done()
	m.Stop()
	return ctx.Err()
}

// restartForwarder replaces the forwarder loop. Callers hold m.mu.
func (m *SyslogManager) restartForwarder() {
	if m.cancel != nil {
		return
	}
	if len(m.config.Forwarders) == 0 || (len(m.feeds) == 0 && m.auditLog == nil) {
		return
	}
	fwdCtx, cancel := context.WithCancel(context.Background())
	m.cancel = cancel
	m.done = make(chan struct{})
	done := m.done
	interval := m.flushEvery
	targets := syslogTargets(m.config.Forwarders)
	feeds := maps.Clone(m.feeds)
	auditEnabled := m.auditLog != nil
	go func() {
		defer close(done)
		var wg sync.WaitGroup
		for _, target := range targets {
			for source, read := range feeds {
				wg.Go(func() {
					m.forwardLoop(fwdCtx, interval, func(ctx context.Context) { m.flushEventPair(ctx, target, source, read) })
				})
			}
			if auditEnabled {
				wg.Go(func() { m.forwardLoop(fwdCtx, interval, func(ctx context.Context) { m.flushAuditTarget(ctx, target) }) })
			}
		}
		wg.Wait()
	}()
}

func (m *SyslogManager) forwardLoop(ctx context.Context, interval time.Duration, flush func(context.Context)) {
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
			flush(ctx)
		}
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
		"audit":                 m.auditStatus(),
		"events":                m.eventStatus(),
	}
}

func formatTime(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.UTC().Format(time.RFC3339Nano)
}

func (m *SyslogManager) formatEvent(ev dpevents.Event, format string) string {
	payload, err := m.formatSourceEvent(ev, format, "", "", 0)
	if err != nil {
		m.log.Errorw("format syslog event", "error", err)
	}
	return payload
}

func (m *SyslogManager) formatSourceEvent(ev dpevents.Event, format string, source evidence.Source, epoch string, offset uint64) (string, error) {
	message := struct {
		dpevents.Event
		Source evidence.Source `json:"source"`
		Epoch  string          `json:"epoch"`
		Offset uint64          `json:"offset,string"`
		Src    string          `json:"src,omitempty"`
		Dst    string          `json:"dst,omitempty"`
	}{ev, source, epoch, offset, syslogEndpoint(ev.SrcIP, ev.SrcPort), syslogEndpoint(ev.DstIP, ev.DstPort)}
	body, err := json.Marshal(message)
	if err != nil {
		return "", err
	}
	if format == "json" {
		return string(body), nil
	}
	return fmt.Sprintf(`<14>1 %s %s containd - event [event@47450 id="%d" source="%s" epoch="%s" offset="%d" kind="%s" src="%s" dst="%s" transport="%s"] %s`,
		ev.Timestamp.UTC().Format(time.RFC3339Nano), syslogHostname(m.hostname), ev.ID,
		escapeSyslogText(string(source), true), escapeSyslogText(epoch, true), offset, escapeSyslogText(ev.Kind, true), escapeSyslogText(syslogEndpoint(ev.SrcIP, ev.SrcPort), true), escapeSyslogText(syslogEndpoint(ev.DstIP, ev.DstPort), true), escapeSyslogText(ev.Transport, true), body), nil
}

// syslogEndpoint is ip alone when port is zero, as for ICMP, and ip:port
// otherwise, with an IPv6 address in brackets: [ip]:port.
func syslogEndpoint(ip string, port uint16) string {
	if port == 0 {
		return ip
	}
	return net.JoinHostPort(ip, strconv.Itoa(int(port)))
}

func syslogHostname(host string) string {
	if strings.TrimSpace(host) == "" {
		return "containd"
	}
	return host
}

// Stop ends the forwarder loop until the next Apply.
func (m *SyslogManager) Stop() {
	m.controlMu.Lock()
	defer m.controlMu.Unlock()
	m.stopAndWait()
}

// stopAndWait never waits while holding a worker's mutex. Callers serialize
// lifecycle changes with controlMu; cancellation interrupts dial and write.
func (m *SyslogManager) stopAndWait() {
	m.mu.Lock()
	cancel, done := m.cancel, m.done
	m.cancel, m.done = nil, nil
	m.mu.Unlock()
	if cancel != nil {
		cancel()
	}
	if done != nil {
		<-done
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
