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

// VPNManager persists VPN service configuration and (later) will supervise VPN daemons or native services.
// Today it only writes a rendered config artifact for inspection.
type VPNManager struct {
	BaseDir string

	mu         sync.Mutex
	lastCfg    config.VPNConfig
	lastRender time.Time
	lastError  string
}

func NewVPNManager(baseDir string) *VPNManager {
	if baseDir == "" {
		baseDir = os.Getenv("CONTAIND_SERVICES_DIR")
	}
	if baseDir == "" {
		baseDir = defaultServicesDir
	}
	return &VPNManager{BaseDir: baseDir}
}

func (m *VPNManager) Apply(ctx context.Context, cfg config.VPNConfig) error {
	_ = ctx
	m.mu.Lock()
	m.lastCfg = cfg
	m.mu.Unlock()

	if err := os.MkdirAll(m.BaseDir, 0o755); err != nil {
		return err
	}
	path := filepath.Join(m.BaseDir, "vpn.json")
	if !cfg.WireGuard.Enabled && !cfg.OpenVPN.Enabled {
		_ = os.Remove(path)
		m.mu.Lock()
		m.lastRender = time.Now().UTC()
		m.lastError = ""
		m.mu.Unlock()
		return nil
	}

	// Render as JSON for now. WireGuard/OpenVPN runtime integration will consume this.
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

func (m *VPNManager) Current() config.VPNConfig {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.lastCfg
}

func (m *VPNManager) Status() map[string]any {
	m.mu.Lock()
	defer m.mu.Unlock()
	return map[string]any{
		"wireguard_enabled": m.lastCfg.WireGuard.Enabled,
		"openvpn_enabled":   m.lastCfg.OpenVPN.Enabled,
		"wg_peers":          len(m.lastCfg.WireGuard.Peers),
		"last_render":       m.lastRender.Format(time.RFC3339Nano),
		"last_error":        m.lastError,
		"note":              "VPN runtime integration is phased (config-only today).",
	}
}

