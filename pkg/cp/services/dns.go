// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

package services

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	commonlog "github.com/tonylturner/containd/pkg/common/logging"
	"github.com/tonylturner/containd/pkg/cp/config"
	"go.uber.org/zap"
)

// DNSManager renders Unbound configuration from persistent DNSConfig.
// In early phases we optionally supervise an embedded Unbound process when
// the binary is present. This keeps the UX "appliance-like" without requiring
// a separate init system.
type DNSManager struct {
	BaseDir       string
	Supervise     bool
	UnboundPath   string
	CheckConfPath string
	ControlPath   string
	OnEvent       func(kind string, attrs map[string]any)

	applyMu    sync.Mutex
	mu         sync.Mutex
	lastCfg    config.DNSConfig
	lastRender time.Time
	lastError  string
	lastStart  time.Time
	lastStop   time.Time
	lastExit   string
	lastConf   string

	cmd     *exec.Cmd
	done    <-chan struct{}
	running bool

	statsCancel context.CancelFunc
	lastStats   map[string]int64
	log         *zap.SugaredLogger
}

// RecordQueries increments DNS traffic counters (success/errors) for telemetry.
func (m *DNSManager) RecordQueries(success int, failures int) {
	if success > 0 && m.OnEvent != nil {
		m.OnEvent("service.dns.queries", map[string]any{"count": success})
	}
	if failures > 0 && m.OnEvent != nil {
		m.OnEvent("service.dns.query_failed", map[string]any{"error_count": failures})
	}
}

func NewDNSManager(baseDir string) *DNSManager {
	if baseDir == "" {
		baseDir = os.Getenv("CONTAIND_SERVICES_DIR")
	}
	if baseDir == "" {
		baseDir = defaultServicesDir
	}
	supervise := true
	if v := strings.TrimSpace(os.Getenv("CONTAIND_SUPERVISE_DNS")); v != "" && v != "1" && !strings.EqualFold(v, "true") {
		supervise = false
	}

	unboundPath, _ := detectBinary([]string{
		strings.TrimSpace(os.Getenv("CONTAIND_UNBOUND_PATH")),
		"/usr/sbin/unbound",
		"/usr/bin/unbound",
	})
	checkConfPath, _ := detectBinary([]string{
		strings.TrimSpace(os.Getenv("CONTAIND_UNBOUND_CHECKCONF_PATH")),
		"/usr/sbin/unbound-checkconf",
		"/usr/bin/unbound-checkconf",
	})
	controlPath, _ := detectBinary([]string{
		strings.TrimSpace(os.Getenv("CONTAIND_UNBOUND_CONTROL_PATH")),
		"/usr/sbin/unbound-control",
		"/usr/bin/unbound-control",
	})

	return &DNSManager{
		BaseDir:       baseDir,
		Supervise:     supervise,
		UnboundPath:   unboundPath,
		CheckConfPath: checkConfPath,
		ControlPath:   controlPath,
		lastStats:     map[string]int64{},
		log:           newDNSLogger(),
	}
}

func newDNSLogger() *zap.SugaredLogger {
	lg, err := commonlog.NewZap("dns", "dns", commonlog.Options{
		FilePath: "/data/logs/dns.log",
		JSON:     true,
		Level:    "info",
	})
	if err != nil {
		return zap.NewNop().Sugar()
	}
	return lg
}

func (m *DNSManager) Apply(ctx context.Context, cfg config.DNSConfig) error {
	if err := validateDaemonService(config.ServicesConfig{DNS: cfg}); err != nil {
		return err
	}
	m.applyMu.Lock()
	defer m.applyMu.Unlock()

	if err := os.MkdirAll(m.BaseDir, 0o755); err != nil {
		return err
	}
	path := filepath.Join(m.BaseDir, "unbound.conf")
	if !cfg.Enabled {
		if err := m.stopLocked(); err != nil {
			return err
		}
		m.emit("service.dns.disabled", map[string]any{})
		_ = os.Remove(path)
		m.mu.Lock()
		m.lastCfg = cfg
		m.lastRender = time.Now().UTC()
		m.lastError = ""
		m.mu.Unlock()
		return nil
	}
	if m.Supervise && m.UnboundPath == "" {
		m.log.Warnw("unbound binary not found; skipping enable", "path", m.UnboundPath)
		return fmt.Errorf("unbound binary not found; set CONTAIND_UNBOUND_PATH or install unbound")
	}

	if err := publishDaemonFiles(ctx, daemonFile{path: path, body: []byte(renderUnbound(cfg)), check: m.checkConfig}); err != nil {
		return serviceConfigError(config.ServiceDNS, err)
	}
	m.mu.Lock()
	m.lastCfg = cfg
	m.lastRender = time.Now().UTC()
	m.lastError = ""
	m.lastConf = path
	m.mu.Unlock()

	if m.Supervise && m.UnboundPath != "" {
		if err := m.startOrReload(path); err != nil {
			m.mu.Lock()
			m.lastError = err.Error()
			m.mu.Unlock()
			m.emit("service.dns.start_failed", map[string]any{"error": err.Error(), "error_count": 1})
			return err
		}
		m.startStatsPoller()
	}

	return nil
}

func (m *DNSManager) Validate(ctx context.Context, cfg config.DNSConfig) error {
	if err := validateDaemonService(config.ServicesConfig{DNS: cfg}); err != nil {
		return err
	}
	if !cfg.Enabled {
		return nil
	}
	dir, err := os.MkdirTemp("", "containd-unbound-validate-*")
	if err != nil {
		return err
	}
	defer os.RemoveAll(dir)
	return serviceConfigError(config.ServiceDNS, publishDaemonFiles(ctx, daemonFile{path: filepath.Join(dir, "unbound.conf"), body: []byte(renderUnbound(cfg)), check: m.checkConfig}))
}

func (m *DNSManager) checkConfig(ctx context.Context, path string) error {
	return checkDaemon(ctx, m.CheckConfPath, path)
}

func (m *DNSManager) Current() config.DNSConfig {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.lastCfg
}

func (m *DNSManager) Status() map[string]any {
	m.mu.Lock()
	defer m.mu.Unlock()
	cfgPath := filepath.Join(m.BaseDir, "unbound.conf")
	return map[string]any{
		"enabled":              m.lastCfg.Enabled,
		"listen_port":          firstNonZero(m.lastCfg.ListenPort, 53),
		"configured_upstreams": len(m.lastCfg.UpstreamServers),
		"last_render":          formatMaybe(m.lastRender),
		"last_error":           m.lastError,
		"installed":            m.UnboundPath != "",
		"binary_path":          m.UnboundPath,
		"supervise":            m.Supervise,
		"running":              m.running,
		"pid":                  pidOrZero(m.cmd),
		"last_start":           formatMaybe(m.lastStart),
		"last_stop":            formatMaybe(m.lastStop),
		"last_exit":            m.lastExit,
		"config_path":          cfgPath,
		"note":                 "Unbound is supervised only when the binary is embedded and supervision is enabled.",
	}
}

func (m *DNSManager) startOrReload(configPath string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.running && m.cmd != nil && m.cmd.Process != nil {
		// Best-effort reload (SIGHUP). If it fails, restart.
		if err := m.cmd.Process.Signal(syscall.SIGHUP); err == nil {
			go m.emit("service.dns.reloaded", map[string]any{"pid": m.cmd.Process.Pid, "count": 1})
			return nil
		}
		if err := m.stopLockedNoLock(); err != nil {
			return err
		}
	}

	// nosemgrep: go.lang.security.audit.dangerous-exec-command.dangerous-exec-command
	cmd := exec.Command(m.UnboundPath, "-d", "-c", configPath)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		return err
	}
	m.cmd = cmd
	done := make(chan struct{})
	m.done = done
	m.running = true
	m.lastStart = time.Now().UTC()
	m.lastExit = ""
	go m.emit("service.dns.started", map[string]any{"pid": cmd.Process.Pid, "config": configPath, "count": 1})

	go func() {
		err := cmd.Wait()
		close(done)
		m.mu.Lock()
		defer m.mu.Unlock()
		if m.cmd != cmd {
			return
		}
		m.running = false
		m.lastStop = time.Now().UTC()
		if err != nil {
			m.lastExit = err.Error()
		} else {
			m.lastExit = "exited"
		}
		exit := m.lastExit
		pid := 0
		if cmd.Process != nil {
			pid = cmd.Process.Pid
		}
		go m.emit("service.dns.exited", map[string]any{"pid": pid, "exit": exit, "error_count": 1})
	}()

	return nil
}

func (m *DNSManager) stopLocked() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.stopLockedNoLock()
}

func (m *DNSManager) stopLockedNoLock() error {
	if !m.running || m.cmd == nil || m.cmd.Process == nil {
		m.running = false
		m.cmd = nil
		return nil
	}

	if err := stopManagedProcess(m.cmd.Process, m.done); err != nil {
		m.lastError = err.Error()
		return err
	}
	go m.emit("service.dns.stopped", map[string]any{"pid": m.cmd.Process.Pid, "count": 1})
	m.running = false
	m.cmd = nil
	m.lastStop = time.Now().UTC()
	m.lastExit = "stopped"
	if m.statsCancel != nil {
		m.statsCancel()
		m.statsCancel = nil
	}
	return nil
}

func (m *DNSManager) emit(kind string, attrs map[string]any) {
	if m == nil || m.OnEvent == nil {
		return
	}
	if attrs == nil {
		attrs = map[string]any{}
	}
	m.OnEvent(kind, attrs)
}

// startStatsPoller periodically executes unbound-control stats_noreset (best-effort) and emits
// query/error deltas into telemetry. It no-ops if control binary is unavailable.
func (m *DNSManager) startStatsPoller() {
	if m.ControlPath == "" {
		return
	}
	if m.statsCancel != nil {
		return
	}
	ctx, cancel := context.WithCancel(context.Background())
	m.statsCancel = cancel
	ticker := time.NewTicker(15 * time.Second)
	go func() {
		defer cancel()
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				m.pollStatsOnce(ctx)
			}
		}
	}()
}

func (m *DNSManager) pollStatsOnce(ctx context.Context) {
	if m.ControlPath == "" {
		return
	}
	m.mu.Lock()
	conf := m.lastConf
	m.mu.Unlock()
	args := []string{"stats_noreset"}
	if strings.TrimSpace(conf) != "" {
		args = append([]string{"-c", conf}, args...)
	}
	cctx, cancel := context.WithTimeout(ctx, 4*time.Second)
	defer cancel()
	// nosemgrep: go.lang.security.audit.dangerous-exec-command.dangerous-exec-command
	cmd := exec.CommandContext(cctx, m.ControlPath, args...)
	out, err := cmd.Output()
	if err != nil {
		return
	}
	lines := strings.Split(string(out), "\n")
	stats := map[string]int64{}
	for _, ln := range lines {
		parts := strings.SplitN(strings.TrimSpace(ln), "=", 2)
		if len(parts) != 2 {
			continue
		}
		v, err := strconv.ParseInt(strings.TrimSpace(parts[1]), 10, 64)
		if err != nil {
			continue
		}
		stats[parts[0]] = v
	}
	queries := stats["num.query.ipv4"] + stats["num.query.ipv6"]
	errors := stats["num.answer.bogus"] + stats["num.answer.servfail"] + stats["num.answer.formerr"]

	m.mu.Lock()
	prevQ := m.lastStats["queries"]
	prevE := m.lastStats["errors"]
	m.lastStats["queries"] = queries
	m.lastStats["errors"] = errors
	m.mu.Unlock()

	dq := queries - prevQ
	de := errors - prevE
	if dq < 0 {
		dq = 0
	}
	if de < 0 {
		de = 0
	}
	if dq > 0 || de > 0 {
		m.RecordQueries(int(dq), int(de))
	}
}
