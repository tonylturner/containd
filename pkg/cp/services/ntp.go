package services

import (
	"context"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/containd/containd/pkg/cp/config"
)

// NTPManager renders OpenNTPD client configuration from persistent NTPConfig.
// Process supervision will land later; this manager only writes config files.
type NTPManager struct {
	BaseDir string

	mu         sync.Mutex
	lastCfg    config.NTPConfig
	lastRender time.Time
	lastError  string
}

func NewNTPManager(baseDir string) *NTPManager {
	if baseDir == "" {
		baseDir = os.Getenv("CONTAIND_SERVICES_DIR")
	}
	if baseDir == "" {
		baseDir = defaultServicesDir
	}
	return &NTPManager{BaseDir: baseDir}
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
	m.mu.Lock()
	m.lastRender = time.Now().UTC()
	m.lastError = ""
	m.mu.Unlock()
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
	return map[string]any{
		"enabled":        m.lastCfg.Enabled,
		"servers_count":  len(m.lastCfg.Servers),
		"last_render":    m.lastRender.Format(time.RFC3339Nano),
		"last_error":     m.lastError,
		"interval_seconds": m.lastCfg.IntervalSeconds,
	}
}
