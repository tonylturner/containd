package services

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/containd/containd/pkg/cp/config"
)

// DHCPManager persists DHCP service configuration and (later) will supervise a DHCP daemon/server.
// Today it only writes a rendered config artifact for inspection.
type DHCPManager struct {
	BaseDir string

	mu         sync.Mutex
	lastCfg    config.DHCPConfig
	lastRender time.Time
	lastError  string
}

func NewDHCPManager(baseDir string) *DHCPManager {
	if baseDir == "" {
		baseDir = os.Getenv("CONTAIND_SERVICES_DIR")
	}
	if baseDir == "" {
		baseDir = defaultServicesDir
	}
	return &DHCPManager{BaseDir: baseDir}
}

func (m *DHCPManager) Apply(ctx context.Context, cfg config.DHCPConfig) error {
	_ = ctx
	m.mu.Lock()
	m.lastCfg = cfg
	m.mu.Unlock()

	if err := os.MkdirAll(m.BaseDir, 0o755); err != nil {
		return err
	}
	path := filepath.Join(m.BaseDir, "dhcp.json")
	if !cfg.Enabled {
		_ = os.Remove(path)
		m.mu.Lock()
		m.lastRender = time.Now().UTC()
		m.lastError = ""
		m.mu.Unlock()
		return nil
	}

	// Render as JSON for now. A real DHCP implementation (native or daemon) will consume this.
	b, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		m.mu.Lock()
		m.lastError = err.Error()
		m.mu.Unlock()
		return err
	}
	if err := os.WriteFile(path, b, 0o600); err != nil {
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

func (m *DHCPManager) Current() config.DHCPConfig {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.lastCfg
}

func (m *DHCPManager) Status() map[string]any {
	m.mu.Lock()
	defer m.mu.Unlock()
	return map[string]any{
		"enabled":       m.lastCfg.Enabled,
		"listen_ifaces": len(m.lastCfg.ListenIfaces),
		"pools":         len(m.lastCfg.Pools),
		"last_render":   m.lastRender.Format(time.RFC3339Nano),
		"last_error":    m.lastError,
		"note":          "DHCP server runtime integration is phased (config-only today).",
	}
}

