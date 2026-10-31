// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

package services

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	commonlog "github.com/tonylturner/containd/pkg/common/logging"
	"github.com/tonylturner/containd/pkg/cp/config"
	"go.uber.org/zap"
)

// NTPManager renders and optionally supervises NTP client configuration.
// Uses chrony (chronyd) as the NTP implementation.
type NTPManager struct {
	BaseDir   string
	Supervise bool
	// NTPDPath is the path to the NTP daemon binary (chronyd).
	NTPDPath string
	// NTPDName identifies the active implementation ("chrony").
	NTPDName string
	OnEvent  func(kind string, attrs map[string]any)

	applyMu    sync.Mutex // serialize renders and daemon restarts
	mu         sync.Mutex
	lastCfg    config.NTPConfig
	lastRender time.Time
	lastError  string
	lastStart  time.Time
	lastStop   time.Time
	lastExit   string
	cmd        *exec.Cmd
	log        *zap.SugaredLogger
}

// RecordSync increments NTP telemetry (successful syncs vs failures).
func (m *NTPManager) RecordSync(success int, failures int) {
	if m == nil || m.OnEvent == nil {
		return
	}
	if success > 0 {
		m.emit("service.ntp.sync", map[string]any{"count": success})
	}
	if failures > 0 {
		m.emit("service.ntp.sync_failed", map[string]any{"error_count": failures})
	}
}

func NewNTPManager(baseDir string) *NTPManager {
	if baseDir == "" {
		baseDir = os.Getenv("CONTAIND_SERVICES_DIR")
	}
	if baseDir == "" {
		baseDir = defaultServicesDir
	}
	supervise := true
	if v := strings.TrimSpace(os.Getenv("CONTAIND_SUPERVISE_NTP")); v != "" && v != "1" && !strings.EqualFold(v, "true") {
		supervise = false
	}

	// Locate chrony, the supported NTP implementation.
	ntpdPath, ntpdName := detectNTPD()

	return &NTPManager{
		BaseDir:   baseDir,
		Supervise: supervise,
		NTPDPath:  ntpdPath,
		NTPDName:  ntpdName,
		log:       newNTPLogger(),
	}
}

// detectNTPD locates chronyd. CONTAIND_NTPD_PATH must point to chronyd.
func detectNTPD() (path string, name string) {
	if p := strings.TrimSpace(os.Getenv("CONTAIND_NTPD_PATH")); p != "" {
		if _, err := os.Stat(p); err == nil && filepath.Base(p) == "chronyd" {
			return p, "chrony"
		}
		return "", "chrony"
	}
	if p, ok := detectBinary([]string{"/usr/sbin/chronyd", "/usr/bin/chronyd"}); ok {
		return p, "chrony"
	}
	return "", "chrony"
}

func newNTPLogger() *zap.SugaredLogger {
	lg, err := commonlog.NewZap("ntp", "ntp", commonlog.Options{
		FilePath: "/data/logs/ntp.log",
		JSON:     true,
		Level:    "info",
	})
	if err != nil {
		return zap.NewNop().Sugar()
	}
	return lg
}

func (m *NTPManager) Apply(ctx context.Context, cfg config.NTPConfig) error {
	if err := validateDaemonService(config.ServicesConfig{NTP: cfg}); err != nil {
		return err
	}
	m.applyMu.Lock()
	defer m.applyMu.Unlock()
	if err := os.MkdirAll(m.BaseDir, 0o755); err != nil {
		return err
	}
	path := m.configPath()
	if !cfg.Enabled {
		m.mu.Lock()
		m.stopLocked()
		m.mu.Unlock()
		_ = os.Remove(path)
		m.mu.Lock()
		m.lastCfg = cfg
		m.lastRender = time.Now().UTC()
		m.lastError = ""
		m.mu.Unlock()
		return nil
	}

	content := m.renderChronyConfig(cfg)
	if err := publishDaemonFiles(ctx, daemonFile{path: path, body: []byte(content), check: m.validate}); err != nil {
		m.mu.Lock()
		m.lastError = err.Error()
		m.mu.Unlock()
		m.emit("service.ntp.validate_failed", map[string]any{"error": err.Error(), "error_count": 1})
		return serviceConfigError(config.ServiceNTP, err)
	}
	m.mu.Lock()
	m.lastCfg = cfg
	m.lastRender = time.Now().UTC()
	m.lastError = ""
	m.mu.Unlock()
	if m.Supervise {
		m.startOrRestart(ctx, path)
	}
	return nil
}

func (m *NTPManager) configPath() string {
	return filepath.Join(m.BaseDir, "chrony.conf")
}

// intervalToPoll rounds seconds up to a bounded log2 poll value for chrony.
// chrony poll values: 4=16s, 6=64s, 8=256s, 10=1024s, 12=4096s.
func intervalToPoll(seconds int) int {
	poll := 4 // minimum: 16 seconds
	for v := 16; v < seconds && poll < 17; v *= 2 {
		poll++
	}
	return poll
}

func (m *NTPManager) Current() config.NTPConfig {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.lastCfg
}

func (m *NTPManager) Status() map[string]any {
	m.mu.Lock()
	defer m.mu.Unlock()
	running := m.cmd != nil && m.cmd.Process != nil
	pid := 0
	if running {
		pid = m.cmd.Process.Pid
	}
	// A zero interval uses chrony's adaptive default (64–1024 seconds).
	var interval any
	var minPoll, maxPoll any
	if m.lastCfg.Enabled && !m.lastRender.IsZero() {
		minPoll, maxPoll = 64, 1024
		if m.lastCfg.IntervalSeconds > 0 {
			seconds := 1 << intervalToPoll(m.lastCfg.IntervalSeconds)
			interval, minPoll, maxPoll = seconds, seconds, seconds
		}
	}
	return map[string]any{
		"min_poll_seconds": minPoll,
		"max_poll_seconds": maxPoll,
		"enabled":          m.lastCfg.Enabled,
		"servers_count":    len(m.lastCfg.Servers),
		"last_render":      formatMaybe(m.lastRender),
		"last_error":       m.lastError,
		"interval_seconds": interval,
		"supervise":        m.Supervise,
		"ntpd_path":        m.NTPDPath,
		"ntpd_name":        m.NTPDName,
		"running":          running,
		"pid":              pid,
		"last_start":       formatMaybe(m.lastStart),
		"last_stop":        formatMaybe(m.lastStop),
		"last_exit":        m.lastExit,
	}
}

func (m *NTPManager) startOrRestart(ctx context.Context, configPath string) {
	earlyExit := m.startDaemon(configPath)
	if earlyExit == nil {
		return
	}
	// Brief stability check: if the daemon dies within 1 second, report failure immediately.
	select {
	case exit := <-earlyExit:
		if exit != "ok" {
			m.log.Errorw("NTP daemon failed immediately after start", "impl", m.NTPDName, "exit", exit)
		}
	case <-time.After(1 * time.Second):
		// Daemon survived initial startup — considered stable.
	}
}

func (m *NTPManager) startDaemon(configPath string) <-chan string {
	m.mu.Lock()
	defer m.mu.Unlock()
	if !m.lastCfg.Enabled {
		return nil
	}
	if m.NTPDPath == "" {
		m.lastError = "NTP daemon not found; supervision skipped"
		m.emit("service.ntp.start_skipped", map[string]any{"reason": m.lastError})
		m.log.Warnw("NTP daemon not found; supervision skipped")
		return nil
	}
	if syscall.Geteuid() != 0 {
		m.lastError = "NTP supervision skipped (requires root)"
		m.emit("service.ntp.start_skipped", map[string]any{"reason": m.lastError})
		m.log.Warnw("NTP supervision skipped; not running as root")
		return nil
	}
	if !hasSysTimeCap() {
		m.lastError = "NTP supervision skipped: CAP_SYS_TIME not available (add --cap-add SYS_TIME to docker run)"
		m.emit("service.ntp.start_skipped", map[string]any{"reason": m.lastError})
		m.log.Warnw("NTP supervision skipped; CAP_SYS_TIME missing")
		return nil
	}
	if m.cmd != nil && m.cmd.Process != nil {
		_ = m.cmd.Process.Signal(os.Interrupt)
		time.Sleep(50 * time.Millisecond)
	}

	// Use background context so the daemon outlives the API request that triggered it.
	// chronyd -d: foreground mode; -f: config file.
	// nosemgrep: go.lang.security.audit.dangerous-exec-command.dangerous-exec-command
	cmd := exec.CommandContext(context.Background(), m.NTPDPath, "-d", "-f", configPath)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		m.lastError = err.Error()
		m.emit("service.ntp.start_failed", map[string]any{"error": err.Error(), "error_count": 1})
		m.log.Errorw("failed to start NTP daemon", "impl", m.NTPDName, "error", err)
		return nil
	}
	m.cmd = cmd
	m.lastError = ""
	m.lastStart = time.Now().UTC()
	m.log.Infow("started NTP daemon", "impl", m.NTPDName, "pid", cmd.Process.Pid, "config", configPath)
	m.emit("service.ntp.started", map[string]any{"pid": cmd.Process.Pid, "config": configPath, "impl": m.NTPDName, "count": 1})

	// Channel to detect early exit (e.g., missing CAP_SYS_TIME).
	earlyExit := make(chan string, 1)
	go func() {
		err := cmd.Wait()
		exit := "ok"
		if err != nil {
			exit = err.Error()
		}
		m.mu.Lock()
		if m.cmd == cmd {
			m.lastExit = exit
			m.lastStop = time.Now().UTC()
			if exit != "ok" {
				m.lastError = "NTP daemon exited unexpectedly: " + exit + " (check CAP_SYS_TIME capability)"
			}
			m.cmd = nil
		}
		m.mu.Unlock()
		m.log.Infow("NTP daemon exited", "impl", m.NTPDName, "pid", cmd.Process.Pid, "exit", exit)
		m.emit("service.ntp.exited", map[string]any{"pid": cmd.Process.Pid, "exit": exit, "error_count": 1})
		earlyExit <- exit
	}()

	return earlyExit
}

func (m *NTPManager) stopLocked() {
	if m.cmd != nil && m.cmd.Process != nil {
		_ = m.cmd.Process.Signal(os.Interrupt)
		m.log.Infow("stopped NTP daemon", "impl", m.NTPDName, "pid", m.cmd.Process.Pid)
		m.emit("service.ntp.stopped", map[string]any{"pid": m.cmd.Process.Pid, "count": 1})
		m.lastStop = time.Now().UTC()
		m.lastExit = "stopped"
	}
	m.cmd = nil
}

func (m *NTPManager) emit(kind string, attrs map[string]any) {
	if m == nil || m.OnEvent == nil {
		return
	}
	m.OnEvent(kind, attrs)
}
