// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

package services

import (
	"context"
	"fmt"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/tonylturner/containd/pkg/common/metrics"
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
	sparkMu   sync.Mutex
	spark     map[string][]int        // primary metric per service (events/traffic)
	counts    map[string]int          // primary totals
	buckets   map[string][]sparkBucket
	errSpark  map[string][]int        // error metric per service
	errCounts map[string]int
	errBks    map[string][]sparkBucket
}

type sparkBucket struct {
	minute int64
	count  int
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
	m.spark = make(map[string][]int)
	m.counts = make(map[string]int)
	m.buckets = make(map[string][]sparkBucket)
	m.errSpark = make(map[string][]int)
	m.errCounts = make(map[string]int)
	m.errBks = make(map[string][]sparkBucket)
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
	if m.DHCP != nil {
		if setter, ok := any(m.DHCP).(interface {
			SetMetricEmitter(func(service string, delta int))
		}); ok {
			setter.SetMetricEmitter(func(service string, delta int) {
				m.IncrementServiceMetric(service, delta)
			})
		}
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
	targetCounts := m.counts
	targetBks := m.buckets
	targetSpark := m.spark
	if isErr {
		targetCounts = m.errCounts
		targetBks = m.errBks
		targetSpark = m.errSpark
	}
	targetCounts[service] += delta
	minute := time.Now().UTC().Unix() / 60
	bks := targetBks[service]
	if len(bks) > 0 && bks[len(bks)-1].minute == minute {
		bks[len(bks)-1].count += delta
	} else {
		bks = append(bks, sparkBucket{minute: minute, count: delta})
	}
	if len(bks) > 7 {
		bks = bks[len(bks)-7:]
	}
	targetBks[service] = bks
	series := make([]int, len(bks))
	for i, b := range bks {
		series[i] = b.count
	}
	targetSpark[service] = series
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

// StartAVWorker starts the AV scan worker in the background.
func (m *Manager) StartAVWorker(ctx context.Context) {
	if m == nil || m.AV == nil {
		return
	}
	m.AV.StartWorker(ctx)
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
	m.updateServiceGauges(cfg)
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
	set("dns", cfg.DNS.Enabled)
	set("ntp", cfg.NTP.Enabled)
	set("syslog", len(cfg.Syslog.Forwarders) > 0)
	set("proxy", cfg.Proxy.Forward.Enabled || cfg.Proxy.Reverse.Enabled)
	set("dhcp", cfg.DHCP.Enabled)
	set("vpn", cfg.VPN.WireGuard.Enabled || cfg.VPN.OpenVPN.Enabled)
	set("av", cfg.AV.Enabled)
}

// TriggerAVUpdate runs a freshclam update once (best-effort) when available.
func (m *Manager) TriggerAVUpdate(ctx context.Context) error {
	if m == nil || m.AV == nil {
		return fmt.Errorf("av manager unavailable")
	}
	return m.AV.RunFreshclamNow(ctx)
}

// Status returns a basic status bundle for UI/CLI.
func (m *Manager) Status() any {
	out := map[string]any{}
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
	if m.AV != nil {
		out["av"] = m.decorateStatus("av", m.AV.Status())
	}
	return out
}

func (m *Manager) decorateStatus(svc string, base any) any {
	m.sparkMu.Lock()
	spark := append([]int(nil), m.spark[svc]...)
	count := m.counts[svc]
	bks := append([]sparkBucket(nil), m.buckets[svc]...)
	errSpark := append([]int(nil), m.errSpark[svc]...)
	errCount := m.errCounts[svc]
	errBks := append([]sparkBucket(nil), m.errBks[svc]...)
	m.sparkMu.Unlock()
	rate := 0.0
	if len(bks) > 0 {
		total := 0
		first := bks[0].minute
		last := bks[len(bks)-1].minute
		for _, b := range bks {
			total += b.count
		}
		minutes := float64((last - first) + 1)
		if minutes <= 0 {
			minutes = 1
		}
		rate = float64(total) / minutes
	}
	errRate := 0.0
	if len(errBks) > 0 {
		total := 0
		first := errBks[0].minute
		last := errBks[len(errBks)-1].minute
		for _, b := range errBks {
			total += b.count
		}
		minutes := float64((last - first) + 1)
		if minutes <= 0 {
			minutes = 1
		}
		errRate = float64(total) / minutes
	}
	if mp, ok := base.(map[string]any); ok {
		mp["sparkline"] = spark
		mp["count"] = count
		mp["rate_per_min"] = rate
		mp["errors_sparkline"] = errSpark
		mp["errors_count"] = errCount
		mp["errors_rate_per_min"] = errRate
		return mp
	}
	return map[string]any{
		"status":    base,
		"sparkline": spark,
		"count":     count,
		"rate_per_min": rate,
		"errors_sparkline": errSpark,
		"errors_count":     errCount,
		"errors_rate_per_min": errRate,
	}
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
	if _, ok := m.counts[service]; ok {
		return true
	}
	if _, ok := m.errCounts[service]; ok {
		return true
	}
	if s, ok := m.spark[service]; ok && len(s) > 0 {
		return true
	}
	if s, ok := m.errSpark[service]; ok && len(s) > 0 {
		return true
	}
	return false
}

// CustomDefsPath proxies to AV manager for API handlers.
func (m *Manager) CustomDefsPath() string {
	if m == nil || m.AV == nil {
		return ""
	}
	return m.AV.CustomDefsPath()
}

// SetEventLister provides a function that returns recent events (newest-first) for syslog forwarding.
func (m *Manager) SetEventLister(fn func(limit int) []dpevents.Event) {
	if m == nil || m.Syslog == nil {
		return
	}
	m.Syslog.SetEventLister(fn)
}
