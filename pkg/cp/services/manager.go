package services

import (
	"context"
	"os"
	"strings"
	"time"

	"github.com/containd/containd/pkg/cp/config"
	dpevents "github.com/containd/containd/pkg/dp/events"
)

// ManagerOptions control where generated service configs are written.
type ManagerOptions struct {
	BaseDir          string
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
	DHCP   *DHCPManager
	VPN    *VPNManager
	AV     *AVManager

	telemetry *dpevents.Store
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
	m := &Manager{
		Syslog: NewSyslogManager(),
		DNS:    NewDNSManager(opts.BaseDir),
		NTP:    NewNTPManager(opts.BaseDir),
		Proxy: NewProxyManager(ProxyOptions{
			BaseDir:   opts.BaseDir,
			Supervise: supervise,
			EnvoyPath: opts.EnvoyPath,
			NginxPath: opts.NginxPath,
			OnEvent:   nil,
		}),
		DHCP: NewDHCPManager(opts.BaseDir),
		VPN:  NewVPNManager(opts.BaseDir),
		AV:   NewAVManager(),
	}
	// Reserve the high bit for management-plane service events to avoid ID collisions
	// with dataplane telemetry IDs.
	m.telemetry = dpevents.NewStoreWithIDBase(2048, 1<<63)
	if m.Syslog != nil {
		m.Syslog.OnEvent = m.recordServiceEvent
	}
	if m.DNS != nil {
		m.DNS.OnEvent = m.recordServiceEvent
	}
	if m.Proxy != nil {
		m.Proxy.OnEvent = m.recordServiceEvent
	}
	if m.VPN != nil {
		m.VPN.OnEvent = m.recordServiceEvent
	}
	if m.NTP != nil {
		m.NTP.OnEvent = m.recordServiceEvent
	}
	if m.AV != nil {
		m.AV.OnEvent = m.recordServiceEvent
	}
	return m
}

func (m *Manager) recordServiceEvent(kind string, attrs map[string]any) {
	if m == nil || m.telemetry == nil {
		return
	}
	ev := dpevents.Event{
		Proto:      "system",
		Kind:       kind,
		Attributes: attrs,
		Timestamp:  time.Now().UTC(),
	}
	m.telemetry.Append(ev)
}

// ListTelemetryEvents returns most-recent-first service/system events recorded by the manager.
func (m *Manager) ListTelemetryEvents(limit int) []dpevents.Event {
	if m == nil || m.telemetry == nil {
		return nil
	}
	return m.telemetry.List(limit)
}

// Validate performs best-effort validation for service configs without changing runtime state.
// When a sub-manager provides a Validate method, it is invoked; otherwise the service is treated
// as "validation not available" and skipped.
func (m *Manager) Validate(ctx context.Context, cfg config.ServicesConfig) error {
	if m.Syslog != nil {
		if v, ok := any(m.Syslog).(interface {
			Validate(context.Context, config.SyslogConfig) error
		}); ok {
			if err := v.Validate(ctx, cfg.Syslog); err != nil {
				return err
			}
		}
	}
	if m.DNS != nil {
		if v, ok := any(m.DNS).(interface {
			Validate(context.Context, config.DNSConfig) error
		}); ok {
			if err := v.Validate(ctx, cfg.DNS); err != nil {
				return err
			}
		}
	}
	if m.NTP != nil {
		if v, ok := any(m.NTP).(interface {
			Validate(context.Context, config.NTPConfig) error
		}); ok {
			if err := v.Validate(ctx, cfg.NTP); err != nil {
				return err
			}
		}
	}
	if m.Proxy != nil {
		if v, ok := any(m.Proxy).(interface {
			Validate(context.Context, config.ProxyConfig) error
		}); ok {
			if err := v.Validate(ctx, cfg.Proxy); err != nil {
				return err
			}
		}
	}
	if m.DHCP != nil {
		if v, ok := any(m.DHCP).(interface {
			Validate(context.Context, config.DHCPConfig) error
		}); ok {
			if err := v.Validate(ctx, cfg.DHCP); err != nil {
				return err
			}
		}
	}
	if m.VPN != nil {
		if v, ok := any(m.VPN).(interface {
			Validate(context.Context, config.VPNConfig) error
		}); ok {
			if err := v.Validate(ctx, cfg.VPN); err != nil {
				return err
			}
		}
	}
	return nil
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
	if m.DHCP != nil {
		if err := m.DHCP.Apply(ctx, cfg.DHCP); err != nil {
			return err
		}
	}
	if m.VPN != nil {
		if err := m.VPN.Apply(ctx, cfg.VPN); err != nil {
			return err
		}
	}
	if m.AV != nil {
		if err := m.AV.Apply(ctx, cfg.AV); err != nil {
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
	if m.DHCP != nil {
		out["dhcp"] = m.DHCP.Status()
	}
	if m.VPN != nil {
		out["vpn"] = m.VPN.Status()
	}
	if m.AV != nil {
		out["av"] = m.AV.Status()
	}
	return out
}

// SetEventLister provides a function that returns recent events (newest-first) for syslog forwarding.
func (m *Manager) SetEventLister(fn func(limit int) []dpevents.Event) {
	if m == nil || m.Syslog == nil {
		return
	}
	m.Syslog.SetEventLister(fn)
}
