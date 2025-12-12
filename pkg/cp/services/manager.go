package services

import (
	"context"

	"github.com/containd/containd/pkg/cp/config"
)

// ManagerOptions control where generated service configs are written.
type ManagerOptions struct {
	BaseDir string
	SuperviseProxies bool
	EnvoyPath        string
	NginxPath        string
}

// Manager applies and renders all control-plane managed services.
// It is intentionally lightweight in early phases: no process lifecycle yet.
type Manager struct {
	Syslog *SyslogManager
	Proxy  *ProxyManager
}

func NewManager(opts ManagerOptions) *Manager {
	return &Manager{
		Syslog: NewSyslogManager(),
		Proxy:  NewProxyManager(ProxyOptions{
			BaseDir:   opts.BaseDir,
			Supervise: opts.SuperviseProxies,
			EnvoyPath: opts.EnvoyPath,
			NginxPath: opts.NginxPath,
		}),
	}
}

// Apply updates in-memory configs and renders service config files.
func (m *Manager) Apply(ctx context.Context, cfg config.ServicesConfig) error {
	if m.Syslog != nil {
		if err := m.Syslog.Apply(ctx, cfg.Syslog); err != nil {
			return err
		}
	}
	if m.Proxy != nil {
		if err := m.Proxy.Apply(ctx, cfg.Proxy); err != nil {
			return err
		}
	}
	return nil
}

// Status returns a basic status bundle for UI/CLI.
func (m *Manager) Status() any {
	out := map[string]any{}
	if m.Syslog != nil {
		out["syslog"] = map[string]any{"configured_forwarders": len(m.Syslog.Current().Forwarders)}
	}
	if m.Proxy != nil {
		out["proxy"] = m.Proxy.Status()
	}
	return out
}
