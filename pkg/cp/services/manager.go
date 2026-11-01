// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

package services

import (
	"context"
	"maps"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/tonylturner/containd/pkg/common/metrics"
	"github.com/tonylturner/containd/pkg/cp/audit"
	"github.com/tonylturner/containd/pkg/cp/config"
	dpevents "github.com/tonylturner/containd/pkg/dp/events"
)

// ManagerOptions control where generated service configs are written.
type ManagerOptions struct {
	BaseDir          string
	SuperviseProxies bool
	EnvoyPath        string
	NginxPath        string
}

// Manager applies and renders all control-plane managed services.
// Sub-managers own rendering and daemon supervision; engine-owned services
// share the same independent fault identities.
type Manager struct {
	Syslog *SyslogManager
	DNS    *DNSManager
	NTP    *NTPManager
	Proxy  *ProxyManager
	DHCP   *DHCPManager
	VPN    *VPNManager

	applyMu    sync.Mutex
	faultMu    sync.Mutex
	faults     []ServiceFault
	faultAudit audit.Store
	telemetry  *dpevents.Store
	sparkMu    sync.Mutex
	primary    map[string]*meter // primary metric per service (events/traffic)
	errs       map[string]*meter // error metric per service
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
	}
	// Reserve the high bit for management-plane service events to avoid ID collisions
	// with dataplane telemetry IDs.
	m.telemetry = dpevents.NewStoreWithIDBase(2048, 1<<63)
	m.primary = make(map[string]*meter)
	m.errs = make(map[string]*meter)
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
	if m.DHCP != nil {
		m.DHCP.SetMetricEmitter(func(delta int, failure bool) {
			m.incrementServiceMetric("dhcp", delta, failure)
		})
	}
	return m
}

func (m *Manager) recordServiceEvent(kind string, attrs map[string]any) {
	if m == nil || m.telemetry == nil {
		return
	}
	delta := 1
	if v, ok := attrs["count"]; ok {
		switch t := v.(type) {
		case int:
			delta = t
		case int64:
			delta = int(t)
		case float64:
			delta = int(t)
		}
	}
	errDelta := 0
	if v, ok := attrs["error_count"]; ok {
		switch t := v.(type) {
		case int:
			errDelta = t
		case int64:
			errDelta = int(t)
		case float64:
			errDelta = int(t)
		}
	}
	services, isErr := canonicalServicesFromKind(kind)
	if strings.HasPrefix(kind, "service.config_fault") || strings.HasPrefix(kind, "service.runtime_fault") {
		if service, ok := attrs["service"].(string); ok {
			services = []string{service}
		}
		isErr = !strings.HasSuffix(kind, ".cleared")
	}
	if len(services) > 0 {
		for _, svc := range services {
			m.incrementServiceMetric(svc, delta, false)
			if isErr {
				if errDelta == 0 {
					errDelta = delta
				}
			}
			if errDelta > 0 {
				m.incrementServiceMetric(svc, errDelta, true)
			}
		}
	}
	ev := dpevents.Event{
		Proto:      "system",
		Kind:       kind,
		Attributes: attrs,
		Timestamp:  time.Now().UTC(),
	}
	m.telemetry.Append(ev)
}

// IncrementServiceMetric allows service managers to bump a per-service counter that feeds
// sparkline + rate telemetry (e.g., traffic volume or anomaly counts).
func (m *Manager) IncrementServiceMetric(service string, delta int) {
	m.incrementServiceMetric(service, delta, false)
}

func (m *Manager) incrementServiceMetric(service string, delta int, isErr bool) {
	if delta == 0 {
		return
	}
	m.sparkMu.Lock()
	defer m.sparkMu.Unlock()
	target := m.primary
	if isErr {
		target = m.errs
	}
	mt := target[service]
	if mt == nil {
		mt = &meter{}
		target[service] = mt
	}
	mt.add(time.Now(), delta)
}

// ListTelemetryEvents returns most-recent-first service/system events recorded by the manager.
func (m *Manager) ListTelemetryEvents(limit int) []dpevents.Event {
	if m == nil || m.telemetry == nil {
		return nil
	}
	return m.telemetry.ListTelemetry(limit)
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

func (m *Manager) updateServiceGauges(cfg config.ServicesConfig) {
	set := func(name string, enabled bool) {
		v := 0.0
		if enabled {
			v = 1.0
		}
		metrics.ServicesRunning.WithLabelValues(name).Set(v)
	}
	set("dns", m.DNS != nil && m.DNS.Status()["running"] == true)
	set("ntp", m.NTP != nil && m.NTP.Status()["running"] == true)
	set("syslog", m.Syslog != nil && m.Syslog.Status()["configured_forwarders"].(int) > 0)
	proxyRunning := false
	if m.Proxy != nil {
		st := m.Proxy.Status()
		proxyRunning = st["envoy_running"] == true || st["nginx_running"] == true
	}
	set("proxy", proxyRunning)
	set("dhcp", false) // Runtime is engine-owned, not inferred from desired config.
	set("wireguard", false)
	ovpn := m.VPN != nil && m.VPN.Status()["openvpn_running"] == true
	set("openvpn", ovpn)
	set("vpn", ovpn)
	for _, fault := range m.Faults() {
		set(fault.Service, false)
		if fault.Service == config.ServiceWireGuard || fault.Service == config.ServiceOpenVPN {
			set("vpn", false)
		}
	}
}

// Status returns a basic status bundle for UI/CLI.
func (m *Manager) Status() any {
	faults := m.Faults()
	out := map[string]any{"faults": faults}
	if m.Syslog != nil {
		out["syslog"] = m.decorateStatus("syslog", m.Syslog.Status())
	}
	if m.DNS != nil {
		out["dns"] = m.decorateStatus("dns", m.DNS.Status())
	}
	if m.NTP != nil {
		out["ntp"] = m.decorateStatus("ntp", m.NTP.Status())
	}
	if m.Proxy != nil {
		out["proxy"] = m.decorateStatus("proxy", m.Proxy.Status())
	}
	if m.hasMetrics("envoy") {
		out["envoy"] = m.decorateStatus("envoy", map[string]any{
			"note": "Telemetry-only counters derived from proxy access logs.",
		})
	}
	if m.hasMetrics("nginx") {
		out["nginx"] = m.decorateStatus("nginx", map[string]any{
			"note": "Telemetry-only counters derived from proxy access logs.",
		})
	}
	if m.DHCP != nil {
		out["dhcp"] = m.decorateStatus("dhcp", m.DHCP.Status())
	}
	if m.VPN != nil {
		out["vpn"] = m.decorateStatus("vpn", m.VPN.Status())
	}
	for _, name := range []string{config.ServiceAV, config.ServiceWireGuard, config.ServiceOpenVPN} {
		out[name] = m.decorateStatus(name, map[string]any{})
	}
	for name, base := range out {
		if name != "faults" {
			out[name] = faultStatus(name, base, faults)
		}
	}
	return out
}

func (m *Manager) decorateStatus(svc string, base any) any {
	m.sparkMu.Lock()
	metrics := meterStatus(m.primary[svc], m.errs[svc])
	m.sparkMu.Unlock()
	if mp, ok := base.(map[string]any); ok {
		maps.Copy(mp, metrics)
		return mp
	}
	metrics["status"] = base
	return metrics
}

func canonicalServicesFromKind(kind string) ([]string, bool) {
	parts := strings.Split(kind, ".")
	if len(parts) < 2 {
		return nil, false
	}
	svc := parts[1]
	switch svc {
	case "envoy", "nginx":
		return []string{"proxy", svc}, strings.Contains(kind, "fail") || strings.Contains(kind, "error")
	case "openvpn":
		svc = "vpn"
	}
	isErr := strings.Contains(kind, "fail") || strings.Contains(kind, "error")
	return []string{svc}, isErr
}

func (m *Manager) hasMetrics(service string) bool {
	m.sparkMu.Lock()
	defer m.sparkMu.Unlock()
	return m.primary[service].active() || m.errs[service].active()
}

// SetEventLister provides a function that returns recent events (newest-first) for syslog forwarding.
func (m *Manager) SetEventLister(fn func(limit int) []dpevents.Event) {
	if m == nil || m.Syslog == nil {
		return
	}
	m.Syslog.SetEventLister(fn)
}

// SetAuditLog makes the syslog forwarders also deliver audit records.
func (m *Manager) SetAuditLog(log audit.ForwardLog) {
	if m == nil || m.Syslog == nil {
		return
	}
	m.Syslog.SetAuditLog(log)
}
