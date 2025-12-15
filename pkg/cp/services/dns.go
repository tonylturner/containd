package services

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/containd/containd/pkg/cp/config"
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
	OnEvent       func(kind string, attrs map[string]any)

	mu         sync.Mutex
	lastCfg    config.DNSConfig
	lastRender time.Time
	lastError  string
	lastStart  time.Time
	lastStop   time.Time
	lastExit   string

	cmd     *exec.Cmd
	running bool
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

	return &DNSManager{
		BaseDir:       baseDir,
		Supervise:     supervise,
		UnboundPath:   unboundPath,
		CheckConfPath: checkConfPath,
	}
}

func (m *DNSManager) Apply(ctx context.Context, cfg config.DNSConfig) error {
	_ = ctx
	m.mu.Lock()
	m.lastCfg = cfg
	m.mu.Unlock()

	if err := os.MkdirAll(m.BaseDir, 0o755); err != nil {
		return err
	}
	path := filepath.Join(m.BaseDir, "unbound.conf")
	if !cfg.Enabled {
		_ = m.stopLocked()
		m.emit("service.dns.disabled", map[string]any{})
		_ = os.Remove(path)
		m.mu.Lock()
		m.lastRender = time.Now().UTC()
		m.lastError = ""
		m.mu.Unlock()
		return nil
	}

	port := cfg.ListenPort
	if port == 0 {
		port = 53
	}
	var b strings.Builder
	b.WriteString("server:\n")
	b.WriteString("  verbosity: 1\n")
	// Ensure Unbound works as a non-root embedded process in containers:
	// - no chroot
	// - no user switching
	// - no pidfile
	// - no syslog (distroless doesn't include it)
	b.WriteString("  username: \"\"\n")
	b.WriteString("  chroot: \"\"\n")
	b.WriteString("  directory: \"/tmp\"\n")
	b.WriteString("  pidfile: \"\"\n")
	b.WriteString("  use-syslog: no\n")
	b.WriteString("  logfile: \"\"\n")
	// Forward-only by default; avoid requiring root trust anchors in early phases.
	b.WriteString("  auto-trust-anchor-file: \"\"\n")
	b.WriteString(fmt.Sprintf("  interface: 0.0.0.0@%d\n", port))
	b.WriteString("  access-control: 0.0.0.0/0 allow\n")
	if cfg.CacheSizeMB > 0 {
		b.WriteString(fmt.Sprintf("  msg-cache-size: %dm\n", cfg.CacheSizeMB))
		b.WriteString(fmt.Sprintf("  rrset-cache-size: %dm\n", cfg.CacheSizeMB))
	}
	if len(cfg.UpstreamServers) > 0 {
		b.WriteString("\nforward-zone:\n")
		b.WriteString("  name: \".\"\n")
		for _, u := range cfg.UpstreamServers {
			u = strings.TrimSpace(u)
			if u == "" {
				continue
			}
			b.WriteString(fmt.Sprintf("  forward-addr: %s\n", u))
		}
	}

	if err := os.WriteFile(path, []byte(b.String()), 0o644); err != nil {
		m.mu.Lock()
		m.lastError = err.Error()
		m.mu.Unlock()
		m.emit("service.dns.render_failed", map[string]any{"error": err.Error()})
		return err
	}
	m.mu.Lock()
	m.lastRender = time.Now().UTC()
	m.lastError = ""
	m.mu.Unlock()

	if m.Supervise && m.UnboundPath != "" {
		if err := m.startOrReload(path); err != nil {
			m.mu.Lock()
			m.lastError = err.Error()
			m.mu.Unlock()
			m.emit("service.dns.start_failed", map[string]any{"error": err.Error()})
			return err
		}
	}

	return nil
}

func (m *DNSManager) Validate(ctx context.Context, cfg config.DNSConfig) error {
	_ = ctx
	if !cfg.Enabled {
		return nil
	}
	port := cfg.ListenPort
	if port == 0 {
		port = 53
	}
	if port < 1 || port > 65535 {
		return fmt.Errorf("dns listenPort invalid: %d", port)
	}
	// If upstreams are present, ensure they are non-empty and trimmed.
	for _, u := range cfg.UpstreamServers {
		if strings.TrimSpace(u) == "" {
			return fmt.Errorf("dns upstreamServers contains empty entry")
		}
	}
	if m.CheckConfPath == "" {
		// No validator binary available; best-effort checks above.
		return nil
	}

	tmpDir, err := os.MkdirTemp("", "containd-unbound-validate-*")
	if err != nil {
		return err
	}
	defer os.RemoveAll(tmpDir)
	path := filepath.Join(tmpDir, "unbound.conf")

	// Render a minimal config identical to Apply(), but without starting processes.
	var b strings.Builder
	b.WriteString("server:\n")
	b.WriteString("  verbosity: 1\n")
	b.WriteString("  username: \"\"\n")
	b.WriteString("  chroot: \"\"\n")
	b.WriteString("  directory: \"/tmp\"\n")
	b.WriteString("  pidfile: \"\"\n")
	b.WriteString("  use-syslog: no\n")
	b.WriteString("  logfile: \"\"\n")
	b.WriteString("  auto-trust-anchor-file: \"\"\n")
	b.WriteString(fmt.Sprintf("  interface: 0.0.0.0@%d\n", port))
	b.WriteString("  access-control: 0.0.0.0/0 allow\n")
	if cfg.CacheSizeMB > 0 {
		b.WriteString(fmt.Sprintf("  msg-cache-size: %dm\n", cfg.CacheSizeMB))
		b.WriteString(fmt.Sprintf("  rrset-cache-size: %dm\n", cfg.CacheSizeMB))
	}
	if len(cfg.UpstreamServers) > 0 {
		b.WriteString("\nforward-zone:\n")
		b.WriteString("  name: \".\"\n")
		for _, u := range cfg.UpstreamServers {
			u = strings.TrimSpace(u)
			if u == "" {
				continue
			}
			b.WriteString(fmt.Sprintf("  forward-addr: %s\n", u))
		}
	}

	if err := os.WriteFile(path, []byte(b.String()), 0o644); err != nil {
		return err
	}

	var out bytes.Buffer
	testCmd := exec.Command(m.CheckConfPath, path)
	testCmd.Stdout = &out
	testCmd.Stderr = &out
	if err := testCmd.Run(); err != nil {
		msg := strings.TrimSpace(out.String())
		if msg == "" {
			msg = err.Error()
		}
		return fmt.Errorf("unbound-checkconf failed: %s", msg)
	}
	return nil
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
		"last_render":          m.lastRender.Format(time.RFC3339Nano),
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

	if m.CheckConfPath != "" {
		var out bytes.Buffer
		testCmd := exec.Command(m.CheckConfPath, configPath)
		testCmd.Stdout = &out
		testCmd.Stderr = &out
		if err := testCmd.Run(); err != nil {
			msg := strings.TrimSpace(out.String())
			if msg == "" {
				msg = err.Error()
			}
			go m.emit("service.dns.validate_failed", map[string]any{"error": msg})
			return fmt.Errorf("unbound-checkconf failed: %s", msg)
		}
	}

	if m.running && m.cmd != nil && m.cmd.Process != nil {
		// Best-effort reload (SIGHUP). If it fails, restart.
		if err := m.cmd.Process.Signal(syscall.SIGHUP); err == nil {
			go m.emit("service.dns.reloaded", map[string]any{"pid": m.cmd.Process.Pid})
			return nil
		}
		_ = m.stopLockedNoLock()
	}

	cmd := exec.Command(m.UnboundPath, "-d", "-c", configPath)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		return err
	}
	m.cmd = cmd
	m.running = true
	m.lastStart = time.Now().UTC()
	m.lastExit = ""
	go m.emit("service.dns.started", map[string]any{"pid": cmd.Process.Pid, "config": configPath})

	go func() {
		err := cmd.Wait()
		m.mu.Lock()
		defer m.mu.Unlock()
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
		go m.emit("service.dns.exited", map[string]any{"pid": pid, "exit": exit})
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

	_ = m.cmd.Process.Signal(syscall.SIGTERM)
	go m.emit("service.dns.stopped", map[string]any{"pid": m.cmd.Process.Pid})
	m.running = false
	m.cmd = nil
	m.lastStop = time.Now().UTC()
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
