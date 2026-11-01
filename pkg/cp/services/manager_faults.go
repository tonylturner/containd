// SPDX-License-Identifier: Apache-2.0
package services

import (
	"context"
	"errors"
	"log/slog"
	"reflect"
	"sort"
	"strconv"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/tonylturner/containd/pkg/cp/audit"
	"github.com/tonylturner/containd/pkg/cp/config"
)

var serviceFaulted = promauto.NewGaugeVec(prometheus.GaugeOpts{
	Namespace: "containd", Subsystem: "services", Name: "faulted",
	Help: "Whether a service has a configuration or runtime fault.",
}, []string{"service"})

// ServiceFault is the public service-status fault contract.
type ServiceFault = config.ServiceFault

// ConfigFaults converts validator errors to sanitized public diagnostics.
func ConfigFaults(in []config.ServiceConfigError) []ServiceFault {
	out := make([]ServiceFault, 0, len(in))
	for _, f := range in {
		message := strconv.QuoteToASCII(f.Err.Error())
		out = append(out, ServiceFault{Service: f.Service, Kind: "config", Message: message[1 : len(message)-1]})
	}
	return out
}

// SeedFaults records faults already emitted in the boot decision.
func (m *Manager) SeedFaults(in []config.ServiceConfigError) {
	m.applyMu.Lock()
	defer m.applyMu.Unlock()
	m.localFaults = ConfigFaults(in)
	m.faultMu.Lock()
	m.faults = ConfigFaults(in)
	m.faultMu.Unlock()
	for _, name := range config.ServiceNames() {
		serviceFaulted.WithLabelValues(name).Set(0)
	}
	for _, f := range in {
		serviceFaulted.WithLabelValues(f.Service).Set(1)
	}
	m.updateServiceGauges()
}

// SetFaultAudit supplies the durable audit sink for subsequent fault changes.
func (m *Manager) SetFaultAudit(sink audit.Store) {
	m.faultMu.Lock()
	m.faultAudit = sink
	m.faultMu.Unlock()
}

// Faults returns a detached, sorted list, including engine-owned service faults.
func (m *Manager) Faults() []ServiceFault {
	m.faultMu.Lock()
	defer m.faultMu.Unlock()
	out := make([]ServiceFault, len(m.faults))
	copy(out, m.faults)
	return out
}

func (m *Manager) publishFaults(faults []ServiceFault) {
	sort.Slice(faults, func(i, j int) bool { return faults[i].Service < faults[j].Service })
	m.faultMu.Lock()
	old := m.faults
	auditSink := m.faultAudit
	m.faults = faults
	m.faultMu.Unlock()
	if reflect.DeepEqual(old, faults) || len(old) == 0 && len(faults) == 0 {
		return
	}
	before, after := map[string]ServiceFault{}, map[string]ServiceFault{}
	for _, f := range old {
		before[f.Service] = f
	}
	for _, f := range faults {
		after[f.Service] = f
	}
	for _, service := range config.ServiceNames() {
		value := 0.0
		if _, ok := after[service]; ok {
			value = 1
		}
		serviceFaulted.WithLabelValues(service).Set(value)
		f, present := after[service]
		if f == before[service] {
			continue
		}
		kind, detail, result := "service."+before[service].Kind+"_fault.cleared", "", "cleared"
		if present {
			kind, detail, result = "service."+f.Kind+"_fault", f.Message, "fault"
		}
		m.recordServiceEvent(kind, map[string]any{"service": service, "error": detail})
		if auditSink != nil {
			if err := auditSink.Add(context.Background(), audit.Record{
				Timestamp: time.Now().UTC(), Actor: "system", Source: "management",
				Action: kind, Target: service, Result: result, Detail: detail,
			}); err != nil {
				slog.Error("record service fault", "service", service, "error", err)
			}
		}
	}
}

// ApplyEffective quarantines typed material/render rejections and ordinary
// runtime failures independently. A failed service never aborts firewall replay.
// The returned services are also the authority for engine apply and compilation.
func (m *Manager) ApplyEffective(ctx context.Context, cfg config.ServicesConfig, initial []config.ServiceConfigError) (config.ServicesConfig, []string) {
	m.applyMu.Lock()
	defer m.applyMu.Unlock()
	faults := ConfigFaults(initial)
	var warnings []string
	apply := func(service string, fn func() error) {
		if err := fn(); err != nil {
			slog.Error("service apply failed", "service", service, "error", err)
			fault := ServiceFault{Service: service, Kind: "runtime", Message: "runtime apply failed"}
			var typed *config.ServiceConfigError
			if errors.As(err, &typed) {
				service = typed.Service
				fault = ConfigFaults([]config.ServiceConfigError{*typed})[0]
			}
			// One identity per service, even if stopping the projection also
			// fails. Keep the originating diagnostic, never claim convergence.
			found := false
			for _, f := range faults {
				found = found || f.Service == service
			}
			if !found {
				faults = append(faults, fault)
			}
			warnings = append(warnings, service+": "+fault.Message)
			config.QuarantineService(&cfg, service)
			// Best-effort stop of any previous runtime, not a retry of the
			// invalid desired content.
			if stopErr := fn(); stopErr != nil {
				warnings = append(warnings, service+": quarantine stop not confirmed")
			}
		}
	}
	if m.Syslog != nil {
		apply(config.ServiceSyslog, func() error { return m.Syslog.Apply(ctx, cfg.Syslog) })
	}
	if m.DNS != nil {
		apply(config.ServiceDNS, func() error { return m.DNS.Apply(ctx, cfg.DNS) })
	}
	if m.NTP != nil {
		apply(config.ServiceNTP, func() error { return m.NTP.Apply(ctx, cfg.NTP) })
	}
	if m.Proxy != nil {
		apply(config.ServiceProxy, func() error { return m.Proxy.Apply(ctx, cfg.Proxy) })
	}
	if m.DHCP != nil {
		apply(config.ServiceDHCP, func() error { return m.DHCP.Apply(ctx, cfg.DHCP) })
	}
	if m.VPN != nil {
		apply(config.ServiceOpenVPN, func() error { return m.VPN.Apply(ctx, cfg.VPN) })
	}
	m.localFaults = faults
	m.publishCombinedFaults()
	return cfg, warnings
}

func faultStatus(service string, base any, faults []ServiceFault) any {
	mp, ok := base.(map[string]any)
	if !ok {
		mp = map[string]any{"status": base}
	}
	for _, fault := range faults {
		if fault.Service == service || service == "vpn" && (fault.Service == config.ServiceOpenVPN || fault.Service == config.ServiceWireGuard) {
			mp["state"] = "faulted"
			mp["fault"] = fault
			break
		}
	}
	return mp
}

// RecordEngineFaults replaces only engine runtime outcomes after a successful
// request. A transport failure cannot certify recovery. Configuration and local
// render faults take precedence over a failed attempt to stop their projection.
func (m *Manager) RecordEngineFaults(faults []config.ServiceFault) {
	m.applyMu.Lock()
	defer m.applyMu.Unlock()
	m.engineFaults = append([]ServiceFault(nil), faults...)
	m.publishCombinedFaults()
}

func (m *Manager) publishCombinedFaults() {
	faults := append([]ServiceFault{}, m.localFaults...)
	for _, engineFault := range m.engineFaults {
		found := false
		for _, localFault := range faults {
			found = found || localFault.Service == engineFault.Service
		}
		if !found {
			faults = append(faults, engineFault)
		}
	}
	m.publishFaults(faults)
	// Faults do not certify a stopped runtime, especially after a failed
	// engine apply or teardown. Only runtime owners publish known states.
	m.updateServiceGauges()
}
