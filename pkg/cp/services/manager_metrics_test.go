// SPDX-License-Identifier: Apache-2.0
package services

import (
	"context"
	"errors"
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/tonylturner/containd/pkg/common/metrics"
	"github.com/tonylturner/containd/pkg/cp/config"
)

// Gather instead of calling WithLabelValues, which would recreate an absent
// series and hide exactly the unknown-state regression these tests exercise.
func serviceGaugeValues(t *testing.T) map[string]float64 {
	t.Helper()
	registry := prometheus.NewRegistry()
	registry.MustRegister(metrics.ServicesRunning)
	families, err := registry.Gather()
	if err != nil {
		t.Fatal(err)
	}
	values := map[string]float64{}
	for _, family := range families {
		for _, metric := range family.Metric {
			for _, label := range metric.Label {
				if label.GetName() == "service" {
					values[label.GetValue()] = metric.GetGauge().GetValue()
				}
			}
		}
	}
	return values
}

func assertServiceGaugeUnknown(t *testing.T, names ...string) {
	t.Helper()
	values := serviceGaugeValues(t)
	for _, name := range names {
		if value, exists := values[name]; exists {
			t.Fatalf("unknown %s published as %v", name, value)
		}
	}
}

func assertServiceGaugeValue(t *testing.T, name string, want float64) {
	t.Helper()
	value, exists := serviceGaugeValues(t)[name]
	if !exists || value != want {
		t.Fatalf("%s: want %v, got %v (present=%t)", name, want, value, exists)
	}
}

func TestServiceGaugesOmitUnobservedEngineState(t *testing.T) {
	metrics.ServicesRunning.Reset()
	t.Cleanup(metrics.ServicesRunning.Reset)
	m := NewManager(ManagerOptions{BaseDir: t.TempDir()})
	m.Syslog, m.DNS, m.NTP, m.Proxy = nil, nil, nil, nil
	for _, enabled := range []bool{false, true} {
		// Delete stale values too, not just avoid creating new ones.
		for _, name := range []string{"dhcp", "wireguard", "vpn"} {
			metrics.ServicesRunning.WithLabelValues(name).Set(1)
		}
		cfg := config.ServicesConfig{
			DHCP: config.DHCPConfig{Enabled: enabled},
			VPN:  config.VPNConfig{WireGuard: config.WireGuardConfig{Enabled: enabled}},
		}
		if _, warnings := m.ApplyEffective(context.Background(), cfg, nil); len(warnings) != 0 {
			t.Fatal(warnings)
		}
		assertServiceGaugeUnknown(t, "dhcp", "wireguard", "vpn")
		assertServiceGaugeValue(t, "openvpn", 0)
	}

	m.VPN.mu.Lock()
	m.VPN.ovpnRunning = true // A local observation, independent of desired config.
	m.VPN.mu.Unlock()
	m.updateServiceGauges()
	assertServiceGaugeValue(t, "openvpn", 1)
	assertServiceGaugeValue(t, "vpn", 1)
	m.RecordEngineFaults([]config.ServiceFault{{Service: config.ServiceWireGuard, Kind: "runtime", Message: "runtime apply failed"}})
	assertServiceGaugeUnknown(t, "dhcp", "wireguard")
	assertServiceGaugeValue(t, "vpn", 1)

	m.VPN.mu.Lock()
	m.VPN.ovpnRunning = false
	m.VPN.mu.Unlock()
	m.RecordEngineFaults(nil)
	assertServiceGaugeValue(t, "openvpn", 0)
	assertServiceGaugeUnknown(t, "vpn", "dhcp", "wireguard")

	for _, name := range []string{"dns", "ntp", "syslog", "proxy"} {
		metrics.ServicesRunning.WithLabelValues(name).Set(1)
	}
	m.VPN = nil
	m.updateServiceGauges()
	assertServiceGaugeUnknown(t, "dns", "ntp", "syslog", "proxy", "openvpn", "vpn")
}

func TestServiceFaultsDoNotInventRuntimeObservations(t *testing.T) {
	metrics.ServicesRunning.Reset()
	t.Cleanup(metrics.ServicesRunning.Reset)
	m := NewManager(ManagerOptions{BaseDir: t.TempDir()})
	m.Syslog, m.DNS, m.NTP, m.Proxy, m.DHCP, m.VPN = nil, nil, nil, nil, nil, nil
	initial := []config.ServiceConfigError{
		{Service: config.ServiceDHCP, Err: errors.New("bad pool")},
		{Service: config.ServiceWireGuard, Err: errors.New("bad key")},
		{Service: config.ServiceAV, Err: errors.New("bad backend")},
	}
	m.SeedFaults(initial)
	assertServiceGaugeUnknown(t, "dhcp", "wireguard", "av", "vpn")
	m.ApplyEffective(context.Background(), config.ServicesConfig{}, initial)
	assertServiceGaugeUnknown(t, "dhcp", "wireguard", "av", "vpn")
	// An engine-owned observation must not be overwritten by management faults.
	metrics.ServicesRunning.WithLabelValues("av").Set(1)
	m.RecordEngineFaults([]config.ServiceFault{
		{Service: config.ServiceDHCP, Kind: "runtime", Message: "runtime apply failed"},
		{Service: config.ServiceWireGuard, Kind: "runtime", Message: "runtime apply failed"},
		{Service: config.ServiceAV, Kind: "runtime", Message: "runtime apply failed"},
	})
	assertServiceGaugeUnknown(t, "dhcp", "wireguard", "vpn")
	assertServiceGaugeValue(t, "av", 1)
	m.SeedFaults(initial)
	assertServiceGaugeValue(t, "av", 1)
}
