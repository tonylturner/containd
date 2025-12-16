package services

import (
	"context"
	"strings"
	"sync"
	"time"

	"github.com/containd/containd/pkg/cp/config"
)

// AVManager handles antivirus configuration and async scan orchestration.
// Initial implementation is a stub with status + validation; scanning pipeline will follow.
type AVManager struct {
	mu         sync.Mutex
	lastCfg    config.AVConfig
	lastRender time.Time
	lastError  string
	OnEvent    func(kind string, attrs map[string]any)
}

func NewAVManager() *AVManager {
	return &AVManager{}
}

func (m *AVManager) Apply(ctx context.Context, cfg config.AVConfig) error {
	_ = ctx
	m.mu.Lock()
	m.lastCfg = cfg
	m.lastRender = time.Now().UTC()
	m.lastError = ""
	m.mu.Unlock()
	m.emit("service.av.updated", map[string]any{
		"enabled": cfg.Enabled,
		"mode":    strings.ToLower(cfg.Mode),
	})
	return nil
}

func (m *AVManager) Current() config.AVConfig {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.lastCfg
}

func (m *AVManager) Status() map[string]any {
	m.mu.Lock()
	defer m.mu.Unlock()
	return map[string]any{
		"enabled":    m.lastCfg.Enabled,
		"mode":       firstNonEmpty(strings.ToLower(m.lastCfg.Mode), "icap"),
		"failPolicy": firstNonEmpty(strings.ToLower(m.lastCfg.FailPolicy), "open"),
		"max_size":   m.lastCfg.MaxSizeBytes,
		"timeout":    m.lastCfg.TimeoutSec,
		"cache_ttl":  m.lastCfg.CacheTTL.String(),
		"icap_servers": func() int {
			if m.lastCfg.ICAP.Servers == nil {
				return 0
			}
			return len(m.lastCfg.ICAP.Servers)
		}(),
		"clamav_socket": strings.TrimSpace(m.lastCfg.ClamAV.SocketPath),
		"last_render":   m.lastRender.Format(time.RFC3339Nano),
		"last_error":    m.lastError,
		"note":          "Scanning pipeline to be wired; this surfaces config/state now.",
	}
}

func (m *AVManager) emit(kind string, attrs map[string]any) {
	if m == nil || m.OnEvent == nil {
		return
	}
	m.OnEvent(kind, attrs)
}
