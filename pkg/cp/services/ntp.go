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

	commonlog "github.com/containd/containd/pkg/common/logging"
	"github.com/containd/containd/pkg/cp/config"
	"go.uber.org/zap"
)

// NTPManager renders and optionally supervises OpenNTPD client configuration.
type NTPManager struct {
	BaseDir      string
	Supervise    bool
	OpenNTPDPath string
	OnEvent      func(kind string, attrs map[string]any)

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
	openntpdPath, _ := detectBinary([]string{
		strings.TrimSpace(os.Getenv("CONTAIND_OPENNTPD_PATH")),
		"/usr/sbin/openntpd",
		"/usr/bin/openntpd",
	})
	return &NTPManager{
		BaseDir:      baseDir,
		Supervise:    supervise,
		OpenNTPDPath: openntpdPath,
		log:          newNTPLogger(),
	}
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
	_ = ctx
	m.mu.Lock()
	m.lastCfg = cfg
	m.mu.Unlock()

	if err := os.MkdirAll(m.BaseDir, 0o755); err != nil {
		return err
	}
	path := filepath.Join(m.BaseDir, "openntpd.conf")
	if !cfg.Enabled {
		m.stopLocked()
		_ = os.Remove(path)
		m.mu.Lock()
		m.lastRender = time.Now().UTC()
		m.lastError = ""
		m.mu.Unlock()
		return nil
	}

	var b strings.Builder
	for _, s := range cfg.Servers {
		s = strings.TrimSpace(s)
		if s == "" {
			continue
		}
		b.WriteString("servers ")
		b.WriteString(s)
		b.WriteString("\n")
	}
	if cfg.IntervalSeconds > 0 {
		b.WriteString("\n# poll-interval-seconds: ")
		b.WriteString(strconv.Itoa(cfg.IntervalSeconds))
		b.WriteString("\n")
	}

	if err := os.WriteFile(path, []byte(b.String()), 0o644); err != nil {
		m.mu.Lock()
		m.lastError = err.Error()
		m.mu.Unlock()
		return err
	}
	if err := m.validate(ctx, path); err != nil {
		return err
	}
	m.mu.Lock()
	m.lastRender = time.Now().UTC()
	m.lastError = ""
	m.mu.Unlock()
	if m.Supervise {
		m.startOrRestart(ctx, path)
	}
	return nil
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
	return map[string]any{
		"enabled":          m.lastCfg.Enabled,
		"servers_count":    len(m.lastCfg.Servers),
		"last_render":      m.lastRender.Format(time.RFC3339Nano),
		"last_error":       m.lastError,
		"interval_seconds": m.lastCfg.IntervalSeconds,
		"supervise":        m.Supervise,
		"openntpd_path":    m.OpenNTPDPath,
		"running":          running,
		"pid":              pid,
		"last_start":       m.lastStart,
		"last_stop":        m.lastStop,
		"last_exit":        m.lastExit,
	}
}

func (m *NTPManager) validate(ctx context.Context, configPath string) error {
	if !m.lastCfg.Enabled {
		return nil
	}
	if m.OpenNTPDPath == "" {
		// No binary available; skip validation but record the missing piece.
		m.mu.Lock()
		m.lastError = "openntpd binary not found (validation skipped)"
		m.mu.Unlock()
		m.emit("service.ntp.validate_skipped", map[string]any{"reason": "openntpd missing"})
		return nil
	}
	testCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	cmd := exec.CommandContext(testCtx, m.OpenNTPDPath, "-n", "-f", configPath)
	if out, err := cmd.CombinedOutput(); err != nil {
		msg := strings.TrimSpace(string(out))
		if msg != "" {
			err = fmt.Errorf("%v: %s", err, msg)
		}
		m.mu.Lock()
		m.lastError = err.Error()
		m.mu.Unlock()
		m.emit("service.ntp.validate_failed", map[string]any{"error": err.Error(), "error_count": 1})
		return err
	}
	return nil
}

func (m *NTPManager) startOrRestart(ctx context.Context, configPath string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if !m.lastCfg.Enabled {
		return
	}
	if m.OpenNTPDPath == "" {
		m.lastError = "openntpd binary not found; supervision skipped"
		m.emit("service.ntp.start_skipped", map[string]any{"reason": m.lastError})
		m.log.Warnw("openntpd binary not found; supervision skipped", "path", m.OpenNTPDPath)
		return
	}
	if syscall.Geteuid() != 0 {
		// OpenNTPD needs privileges to step the clock; avoid failing config applies when not root.
		m.lastError = "openntpd supervision skipped (requires root/CAP_SYS_TIME)"
		m.emit("service.ntp.start_skipped", map[string]any{"reason": m.lastError})
		m.log.Warnw("openntpd supervision skipped; insufficient privileges")
		return
	}
	if m.cmd != nil && m.cmd.Process != nil {
		_ = m.cmd.Process.Signal(os.Interrupt)
		time.Sleep(50 * time.Millisecond)
	}
	cmd := exec.CommandContext(ctx, m.OpenNTPDPath, "-d", "-f", configPath)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		m.lastError = err.Error()
		m.emit("service.ntp.start_failed", map[string]any{"error": err.Error(), "error_count": 1})
		m.log.Errorw("failed to start openntpd", "error", err)
		return
	}
	m.cmd = cmd
	m.lastError = ""
	m.lastStart = time.Now().UTC()
	m.log.Infow("started openntpd", "pid", cmd.Process.Pid, "config", configPath)
	m.emit("service.ntp.started", map[string]any{"pid": cmd.Process.Pid, "config": configPath, "count": 1})
	go func() {
		err := cmd.Wait()
		exit := "ok"
		if err != nil {
			exit = err.Error()
		}
		m.mu.Lock()
		m.lastExit = exit
		m.lastStop = time.Now().UTC()
		m.mu.Unlock()
		m.log.Infow("openntpd exited", "pid", cmd.Process.Pid, "exit", exit)
		m.emit("service.ntp.exited", map[string]any{"pid": cmd.Process.Pid, "exit": exit, "error_count": 1})
	}()
}

func (m *NTPManager) stopLocked() {
	if m.cmd != nil && m.cmd.Process != nil {
		_ = m.cmd.Process.Signal(os.Interrupt)
		m.log.Infow("stopped openntpd", "pid", m.cmd.Process.Pid)
		m.emit("service.ntp.stopped", map[string]any{"pid": m.cmd.Process.Pid, "count": 1})
	}
	m.cmd = nil
}

func (m *NTPManager) emit(kind string, attrs map[string]any) {
	if m == nil || m.OnEvent == nil {
		return
	}
	m.OnEvent(kind, attrs)
}
