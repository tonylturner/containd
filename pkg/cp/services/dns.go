package services

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/containd/containd/pkg/cp/config"
)

// DNSManager renders Unbound configuration from persistent DNSConfig.
// Process supervision will land later; this manager only writes config files.
type DNSManager struct {
	BaseDir string

	mu         sync.Mutex
	lastCfg    config.DNSConfig
	lastRender time.Time
	lastError  string
}

func NewDNSManager(baseDir string) *DNSManager {
	if baseDir == "" {
		baseDir = os.Getenv("CONTAIND_SERVICES_DIR")
	}
	if baseDir == "" {
		baseDir = defaultServicesDir
	}
	return &DNSManager{BaseDir: baseDir}
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
		return err
	}
	m.mu.Lock()
	m.lastRender = time.Now().UTC()
	m.lastError = ""
	m.mu.Unlock()
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
	return map[string]any{
		"enabled":              m.lastCfg.Enabled,
		"listen_port":          firstNonZero(m.lastCfg.ListenPort, 53),
		"configured_upstreams": len(m.lastCfg.UpstreamServers),
		"last_render":          m.lastRender.Format(time.RFC3339Nano),
		"last_error":           m.lastError,
	}
}

func firstNonZero(v int, def int) int {
	if v != 0 {
		return v
	}
	return def
}

