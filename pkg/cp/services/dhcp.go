package services

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"sync"
	"time"

	commonlog "github.com/containd/containd/pkg/common/logging"
	"github.com/containd/containd/pkg/cp/config"
	"go.uber.org/zap"
)

// DHCPManager persists DHCP service configuration and (later) will supervise a DHCP daemon/server.
// Today it only writes a rendered config artifact for inspection.
type DHCPManager struct {
	BaseDir string

	mu         sync.Mutex
	lastCfg    config.DHCPConfig
	lastRender time.Time
	lastError  string

	onMetric func(service string, delta int)
	log      *zap.SugaredLogger
}

func NewDHCPManager(baseDir string) *DHCPManager {
	if baseDir == "" {
		baseDir = os.Getenv("CONTAIND_SERVICES_DIR")
	}
	if baseDir == "" {
		baseDir = defaultServicesDir
	}
	return &DHCPManager{
		BaseDir: baseDir,
		log:     newDHCPLogger(),
	}
}

func newDHCPLogger() *zap.SugaredLogger {
	lg, err := commonlog.NewZap("dhcp", "dhcp", commonlog.Options{
		FilePath: "/data/logs/dhcp.log",
		JSON:     true,
		Level:    "info",
	})
	if err != nil {
		return zap.NewNop().Sugar()
	}
	return lg
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
		m.log.Errorw("failed to render dhcp config", "error", err)
		return err
	}
	if err := os.WriteFile(path, b, 0o600); err != nil {
		m.mu.Lock()
		m.lastError = err.Error()
		m.mu.Unlock()
		m.log.Errorw("failed to write dhcp config", "path", path, "error", err)
		return err
	}
	m.mu.Lock()
	m.lastRender = time.Now().UTC()
	m.lastError = ""
	m.mu.Unlock()
	m.log.Infow("rendered dhcp config", "path", path)
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
		"reservations":  len(m.lastCfg.Reservations),
		"last_render":   m.lastRender.Format(time.RFC3339Nano),
		"last_error":    m.lastError,
		"note":          "DHCP server runtime integration is phased (config-only today).",
	}
}

// IncrementLeaseMetric can be called by the DHCP runtime (when added) to track issued leases.
func (m *DHCPManager) IncrementLeaseMetric(delta int, failure bool) {
	if m == nil || m.onMetric == nil {
		return
	}
	if failure {
		m.onMetric("dhcp", 0)
		m.onMetric("dhcp_error", delta)
		return
	}
	m.onMetric("dhcp", delta)
}

// SetMetricEmitter is used by the top-level manager to provide IncrementServiceMetric callback.
func (m *DHCPManager) SetMetricEmitter(fn func(service string, delta int)) {
	m.onMetric = fn
}
