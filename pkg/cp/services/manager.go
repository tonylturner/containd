package services

import (
	"context"
	"os"
	"strings"

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
	DNS    *DNSManager
	NTP    *NTPManager
	Proxy  *ProxyManager
}

func NewManager(opts ManagerOptions) *Manager {
	supervise := opts.SuperviseProxies
	if !supervise {
		// Default to supervising proxies when embedded binaries exist.
		// Operators can disable by setting CONTAIND_SUPERVISE_PROXIES=0.
		if v := strings.TrimSpace(os.Getenv("CONTAIND_SUPERVISE_PROXIES")); v == "" || v == "1" || strings.EqualFold(v, "true") {
			supervise = true
		}
	}
	return &Manager{
		Syslog: NewSyslogManager(),
		DNS:    NewDNSManager(opts.BaseDir),
		NTP:    NewNTPManager(opts.BaseDir),
		Proxy:  NewProxyManager(ProxyOptions{
			BaseDir:   opts.BaseDir,
			Supervise: supervise,
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
	if m.DNS != nil {
		if err := m.DNS.Apply(ctx, cfg.DNS); err != nil {
			return err
		}
	}
	if m.NTP != nil {
		if err := m.NTP.Apply(ctx, cfg.NTP); err != nil {
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
	if m.DNS != nil {
		out["dns"] = m.DNS.Status()
	}
	if m.NTP != nil {
		out["ntp"] = m.NTP.Status()
	}
	if m.Proxy != nil {
		out["proxy"] = m.Proxy.Status()
	}
	return out
}
