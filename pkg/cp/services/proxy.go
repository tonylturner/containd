// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

package services

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	commonlog "github.com/tonylturner/containd/pkg/common/logging"
	"github.com/tonylturner/containd/pkg/cp/config"
	"go.uber.org/zap"
)

// defaultServicesDir must be writable in the single-container appliance image.
// In docker-compose we mount a persistent volume at /data.
const defaultServicesDir = "/data/services"

const defaultCertsDir = "/data/certs"

type ProxyOptions struct {
	BaseDir   string
	Supervise bool
	EnvoyPath string
	NginxPath string
	OnEvent   func(kind string, attrs map[string]any)
}

// ProxyManager renders Envoy (forward) and Nginx (reverse) configs from persistent models.
// If Supervise is enabled and binaries exist, it will also start/stop them.
type ProxyManager struct {
	BaseDir   string
	Supervise bool
	EnvoyPath string
	NginxPath string
	CertsDir  string

	OnEvent func(kind string, attrs map[string]any)

	applyMu        sync.Mutex
	mu             sync.Mutex
	lastCfg        config.ProxyConfig
	envoyCmd       *exec.Cmd
	nginxCmd       *exec.Cmd
	envoyDone      <-chan struct{}
	nginxDone      <-chan struct{}
	lastEnvoyError string
	lastNginxError string
	lastEnvoyStart time.Time
	lastNginxStart time.Time
	lastEnvoyStop  time.Time
	lastNginxStop  time.Time
	lastEnvoyExit  string
	lastNginxExit  string
	lastRender     time.Time
	log            *zap.SugaredLogger

	// Optional traffic emitters (e.g., access log tailers) can call these helpers.
	envoyAccessCancel context.CancelFunc
	envoyAccessPath   string
	nginxAccessCancel context.CancelFunc
	nginxAccessPath   string
}

// RecordForwardRequests increments the proxy traffic counter for Envoy forward proxy.
func (m *ProxyManager) RecordForwardRequests(count int, errs int) {
	if count < 0 {
		count = 0
	}
	if errs < 0 {
		errs = 0
	}
	if count > 0 {
		m.emit("service.envoy.requests", map[string]any{"count": count})
	}
	if errs > 0 {
		m.emit("service.envoy.errors", map[string]any{"error_count": errs})
	}
}

// RecordReverseRequests increments the proxy traffic counter for Nginx reverse proxy.
func (m *ProxyManager) RecordReverseRequests(count int, errs int) {
	if count < 0 {
		count = 0
	}
	if errs < 0 {
		errs = 0
	}
	if count > 0 {
		m.emit("service.nginx.requests", map[string]any{"count": count})
	}
	if errs > 0 {
		m.emit("service.nginx.errors", map[string]any{"error_count": errs})
	}
}

func NewProxyManager(opts ProxyOptions) *ProxyManager {
	baseDir := opts.BaseDir
	if baseDir == "" {
		baseDir = os.Getenv("CONTAIND_SERVICES_DIR")
	}
	if baseDir == "" {
		baseDir = defaultServicesDir
	}
	certsDir := strings.TrimSpace(os.Getenv("CONTAIND_CERTS_DIR"))
	if certsDir == "" {
		certsDir = defaultCertsDir
	}
	envoyPath := opts.EnvoyPath
	if envoyPath == "" {
		envoyPath = "/usr/bin/envoy"
	}
	nginxPath := opts.NginxPath
	if nginxPath == "" {
		nginxPath = "/usr/sbin/nginx"
	}
	lg, err := commonlog.NewZap("proxy", "proxy", commonlog.Options{
		FilePath: "/data/logs/proxy.log",
		JSON:     true,
		Level:    "info",
	})
	if err != nil {
		lg = zap.NewNop().Sugar()
	}
	return &ProxyManager{
		BaseDir:   baseDir,
		Supervise: opts.Supervise,
		EnvoyPath: envoyPath,
		NginxPath: nginxPath,
		CertsDir:  certsDir,
		log:       lg,
		OnEvent:   opts.OnEvent,
	}
}

func (m *ProxyManager) Apply(ctx context.Context, cfg config.ProxyConfig) error {
	m.applyMu.Lock()
	defer m.applyMu.Unlock()
	if err := m.checkProxyConfig(cfg); err != nil {
		return serviceConfigError(config.ServiceProxy, err)
	}
	if err := m.prepareRenderDirs(); err != nil {
		return err
	}
	files, err := m.proxyFiles(cfg)
	if err != nil {
		return serviceConfigError(config.ServiceProxy, err)
	}
	if err := publishDaemonFiles(ctx, files...); err != nil {
		return serviceConfigError(config.ServiceProxy, err)
	}
	m.mu.Lock()
	m.lastCfg = cfg
	m.lastRender = time.Now().UTC()
	m.mu.Unlock()
	if m.Supervise {
		if err := m.ensureProcesses(ctx, cfg); err != nil {
			return err
		}
	}
	m.syncAccessTailers(cfg)
	return nil
}

func (m *ProxyManager) ensureProcesses(ctx context.Context, cfg config.ProxyConfig) error {
	var errs []error
	if cfg.Forward.Enabled {
		errs = append(errs, m.startOrRestartEnvoy(ctx))
	} else {
		errs = append(errs, m.stopEnvoy())
	}
	if cfg.Reverse.Enabled && len(cfg.Reverse.Sites) > 0 {
		errs = append(errs, m.startOrRestartNginx(ctx))
	} else {
		errs = append(errs, m.stopNginx())
	}
	return errors.Join(errs...)
}

func (m *ProxyManager) startOrRestartEnvoy(ctx context.Context) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, err := os.Stat(m.EnvoyPath); err != nil {
		m.lastEnvoyError = fmt.Sprintf("envoy binary not found at %s", m.EnvoyPath)
		m.log.Warnw("envoy binary not found; supervision skipped", "path", m.EnvoyPath)
		return errors.New(m.lastEnvoyError)
	}
	configPath := filepath.Join(m.BaseDir, "envoy-forward.yaml")
	if info, err := os.Stat(configPath); err != nil || info.Size() == 0 {
		m.lastEnvoyError = fmt.Sprintf("envoy config missing or empty at %s", configPath)
		m.log.Warnw("envoy config missing; skipping start", "config", configPath)
		return errors.New(m.lastEnvoyError)
	}
	if m.envoyCmd != nil && m.envoyCmd.Process != nil {
		if err := stopManagedProcess(m.envoyCmd.Process, m.envoyDone); err != nil {
			m.lastEnvoyError = err.Error()
			return err
		}
	}
	// Use background context so envoy outlives the API request that triggered it.
	// nosemgrep: go.lang.security.audit.dangerous-exec-command.dangerous-exec-command
	cmd := exec.CommandContext(context.Background(), m.EnvoyPath, "-c", configPath, "--log-level", "info")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		m.lastEnvoyError = err.Error()
		m.log.Errorw("failed to start envoy", "error", err)
		m.emit("service.envoy.start_failed", map[string]any{"error": err.Error(), "error_count": 1})
		return errors.New(m.lastEnvoyError)
	}
	m.envoyCmd = cmd
	done := make(chan struct{})
	m.envoyDone = done
	m.lastEnvoyError = ""
	m.lastEnvoyStart = time.Now().UTC()
	m.lastEnvoyExit = ""
	m.emit("service.envoy.started", map[string]any{"pid": cmd.Process.Pid, "config": configPath, "count": 1})
	pid := cmd.Process.Pid
	go func(cmd *exec.Cmd, pid int) {
		err := cmd.Wait()
		close(done)
		exit := "exited"
		if err != nil {
			exit = err.Error()
		}
		m.mu.Lock()
		if m.envoyCmd == cmd {
			m.envoyCmd = nil
			m.lastEnvoyStop = time.Now().UTC()
			m.lastEnvoyExit = exit
		}
		m.mu.Unlock()
		m.emit("service.envoy.exited", map[string]any{"pid": pid, "exit": exit, "error_count": 1})
	}(cmd, pid)
	return nil
}

func (m *ProxyManager) stopEnvoy() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.envoyCmd != nil && m.envoyCmd.Process != nil {
		if err := stopManagedProcess(m.envoyCmd.Process, m.envoyDone); err != nil {
			m.lastEnvoyError = err.Error()
			return err
		}
		m.emit("service.envoy.stopped", map[string]any{"pid": m.envoyCmd.Process.Pid, "count": 1})
	}
	m.envoyCmd = nil
	m.lastEnvoyStop = time.Now().UTC()
	return nil
}

func (m *ProxyManager) startOrRestartNginx(ctx context.Context) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, err := os.Stat(m.NginxPath); err != nil {
		m.lastNginxError = fmt.Sprintf("nginx binary not found at %s", m.NginxPath)
		m.log.Warnw("nginx binary missing; supervision skipped", "path", m.NginxPath)
		return errors.New(m.lastNginxError)
	}
	configPath := filepath.Join(m.BaseDir, "nginx-reverse.conf")
	if info, err := os.Stat(configPath); err != nil || info.Size() == 0 {
		m.lastNginxError = fmt.Sprintf("nginx config missing or empty at %s", configPath)
		m.log.Warnw("nginx config missing; skipping start", "config", configPath)
		return errors.New(m.lastNginxError)
	}
	if m.nginxCmd != nil && m.nginxCmd.Process != nil {
		if err := stopManagedProcess(m.nginxCmd.Process, m.nginxDone); err != nil {
			m.lastNginxError = err.Error()
			return err
		}
	}
	// Use background context so nginx outlives the API request that triggered it.
	// nosemgrep: go.lang.security.audit.dangerous-exec-command.dangerous-exec-command
	cmd := exec.CommandContext(context.Background(), m.NginxPath, "-c", configPath, "-g", "daemon off;")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		m.lastNginxError = err.Error()
		m.log.Errorw("failed to start nginx", "error", err)
		m.emit("service.nginx.start_failed", map[string]any{"error": err.Error(), "error_count": 1})
		return errors.New(m.lastNginxError)
	}
	m.nginxCmd = cmd
	done := make(chan struct{})
	m.nginxDone = done
	m.lastNginxError = ""
	m.lastNginxStart = time.Now().UTC()
	m.lastNginxExit = ""
	m.emit("service.nginx.started", map[string]any{"pid": cmd.Process.Pid, "config": configPath, "count": 1})
	pid := cmd.Process.Pid
	go func(cmd *exec.Cmd, pid int) {
		err := cmd.Wait()
		close(done)
		exit := "exited"
		if err != nil {
			exit = err.Error()
		}
		m.mu.Lock()
		if m.nginxCmd == cmd {
			m.nginxCmd = nil
			m.lastNginxStop = time.Now().UTC()
			m.lastNginxExit = exit
		}
		m.mu.Unlock()
		m.emit("service.nginx.exited", map[string]any{"pid": pid, "exit": exit, "error_count": 1})
	}(cmd, pid)
	return nil
}

func (m *ProxyManager) stopNginx() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.nginxCmd != nil && m.nginxCmd.Process != nil {
		if err := stopManagedProcess(m.nginxCmd.Process, m.nginxDone); err != nil {
			m.lastNginxError = err.Error()
			return err
		}
		m.emit("service.nginx.stopped", map[string]any{"pid": m.nginxCmd.Process.Pid, "count": 1})
	}
	m.nginxCmd = nil
	m.lastNginxStop = time.Now().UTC()
	return nil
}

func (m *ProxyManager) Status() map[string]any {
	m.mu.Lock()
	defer m.mu.Unlock()
	envoyRunning := m.envoyCmd != nil && m.envoyCmd.Process != nil
	nginxRunning := m.nginxCmd != nil && m.nginxCmd.Process != nil
	envoyPID := 0
	nginxPID := 0
	if envoyRunning {
		envoyPID = m.envoyCmd.Process.Pid
	}
	if nginxRunning {
		nginxPID = m.nginxCmd.Process.Pid
	}
	return map[string]any{
		"forward_enabled":  m.lastCfg.Forward.Enabled,
		"reverse_enabled":  m.lastCfg.Reverse.Enabled,
		"envoy_path":       m.EnvoyPath,
		"nginx_path":       m.NginxPath,
		"envoy_running":    envoyRunning,
		"nginx_running":    nginxRunning,
		"envoy_pid":        envoyPID,
		"nginx_pid":        nginxPID,
		"envoy_last_start": formatMaybe(m.lastEnvoyStart),
		"nginx_last_start": formatMaybe(m.lastNginxStart),
		"envoy_last_stop":  formatMaybe(m.lastEnvoyStop),
		"nginx_last_stop":  formatMaybe(m.lastNginxStop),
		"envoy_last_exit":  m.lastEnvoyExit,
		"nginx_last_exit":  m.lastNginxExit,
		"envoy_last_error": m.lastEnvoyError,
		"nginx_last_error": m.lastNginxError,
		"last_render":      formatMaybe(m.lastRender),
		"rendered_files":   m.DescribeRendered(),
	}
}

func (m *ProxyManager) emit(kind string, attrs map[string]any) {
	if m.OnEvent != nil {
		m.OnEvent(kind, attrs)
	}
}

func (m *ProxyManager) syncAccessTailers(cfg config.ProxyConfig) {
	if !m.Supervise {
		m.stopEnvoyAccessTailer()
		m.stopNginxAccessTailer()
		return
	}
	logDir := filepath.Join(filepath.Dir(m.BaseDir), "logs")
	if cfg.Forward.Enabled && cfg.Forward.LogRequests {
		m.startEnvoyAccessTailer(filepath.Join(logDir, "envoy-access.log"))
	} else {
		m.stopEnvoyAccessTailer()
	}
	if cfg.Reverse.Enabled && len(cfg.Reverse.Sites) > 0 {
		m.startNginxAccessTailer(filepath.Join(logDir, "nginx-access.log"))
	} else {
		m.stopNginxAccessTailer()
	}
}

func (m *ProxyManager) startEnvoyAccessTailer(path string) {
	m.mu.Lock()
	if m.envoyAccessCancel != nil && m.envoyAccessPath == path {
		m.mu.Unlock()
		return
	}
	if m.envoyAccessCancel != nil {
		m.envoyAccessCancel()
		m.envoyAccessCancel = nil
	}
	ctx, cancel := context.WithCancel(context.Background())
	m.envoyAccessCancel = cancel
	m.envoyAccessPath = path
	m.mu.Unlock()

	go m.tailAccessLog(ctx, "envoy", path, m.RecordForwardRequests)
}

func (m *ProxyManager) stopEnvoyAccessTailer() {
	m.mu.Lock()
	if m.envoyAccessCancel != nil {
		m.envoyAccessCancel()
		m.envoyAccessCancel = nil
		m.envoyAccessPath = ""
	}
	m.mu.Unlock()
}

func (m *ProxyManager) startNginxAccessTailer(path string) {
	m.mu.Lock()
	if m.nginxAccessCancel != nil && m.nginxAccessPath == path {
		m.mu.Unlock()
		return
	}
	if m.nginxAccessCancel != nil {
		m.nginxAccessCancel()
		m.nginxAccessCancel = nil
	}
	ctx, cancel := context.WithCancel(context.Background())
	m.nginxAccessCancel = cancel
	m.nginxAccessPath = path
	m.mu.Unlock()

	go m.tailAccessLog(ctx, "nginx", path, m.RecordReverseRequests)
}

func (m *ProxyManager) stopNginxAccessTailer() {
	m.mu.Lock()
	if m.nginxAccessCancel != nil {
		m.nginxAccessCancel()
		m.nginxAccessCancel = nil
		m.nginxAccessPath = ""
	}
	m.mu.Unlock()
}

func (m *ProxyManager) tailAccessLog(ctx context.Context, service string, path string, record func(count int, errs int)) {
	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		f, err := os.Open(path)
		if err != nil {
			m.emit("service."+service+".access_log_open_failed", map[string]any{"error": err.Error(), "error_count": 1})
			time.Sleep(1 * time.Second)
			continue
		}
		if _, err := f.Seek(0, io.SeekEnd); err != nil {
			_ = f.Close()
			m.emit("service."+service+".access_log_seek_failed", map[string]any{"error": err.Error(), "error_count": 1})
			time.Sleep(1 * time.Second)
			continue
		}

		reader := bufio.NewReader(f)
		for {
			line, err := reader.ReadString('\n')
			if err != nil {
				if err == io.EOF {
					select {
					case <-ctx.Done():
						_ = f.Close()
						return
					case <-time.After(250 * time.Millisecond):
						continue
					}
				}
				m.emit("service."+service+".access_log_read_failed", map[string]any{"error": err.Error(), "error_count": 1})
				break
			}
			status := parseAccessStatus(line)
			errs := 0
			if status >= 400 {
				errs = 1
			}
			record(1, errs)
		}
		_ = f.Close()
		time.Sleep(250 * time.Millisecond)
	}
}

func parseAccessStatus(line string) int {
	idx := strings.Index(line, "status=")
	if idx < 0 {
		return 0
	}
	raw := strings.TrimSpace(line[idx+len("status="):])
	end := 0
	for end < len(raw) {
		if raw[end] < '0' || raw[end] > '9' {
			break
		}
		end++
	}
	if end == 0 {
		return 0
	}
	val, err := strconv.Atoi(raw[:end])
	if err != nil {
		return 0
	}
	return val
}

// DescribeRendered returns a human-readable list of rendered files for debugging.
func (m *ProxyManager) DescribeRendered() []string {
	return []string{
		fmt.Sprintf("%s/envoy-forward.yaml", m.BaseDir),
		fmt.Sprintf("%s/nginx-reverse.conf", m.BaseDir),
	}
}
