// SPDX-License-Identifier: Apache-2.0
package services

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"testing"

	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/tonylturner/containd/pkg/common/metrics"
	"github.com/tonylturner/containd/pkg/cp/audit"
	"github.com/tonylturner/containd/pkg/cp/config"
)

func TestServiceFaultJSONContract(t *testing.T) {
	fault := ServiceFault{Service: "wireguard", Kind: "config", Message: "invalid interface"}
	data, err := json.Marshal(fault)
	if err != nil || string(data) != `{"service":"wireguard","kind":"config","message":"invalid interface"}` {
		t.Fatalf("service fault contract changed: %s %v", data, err)
	}
	m := NewManager(ManagerOptions{BaseDir: t.TempDir()})
	data, err = json.Marshal(m.Faults())
	if err != nil || string(data) != "[]" {
		t.Fatalf("empty fault set must be an array: %s %v", data, err)
	}
}

func TestManagerMaterialAndRuntimeQuarantine(t *testing.T) {
	for _, runtimeFailure := range []bool{false, true} {
		t.Run(map[bool]string{false: "material", true: "runtime"}[runtimeFailure], func(t *testing.T) {
			dir := t.TempDir()
			m := NewManager(ManagerOptions{BaseDir: dir})
			m.Syslog, m.NTP, m.VPN = nil, nil, nil
			cfg := config.ServicesConfig{DHCP: config.DHCPConfig{Enabled: true}}
			service, kind := config.ServiceProxy, "config"
			if runtimeFailure {
				service, kind = config.ServiceDNS, "runtime"
				m.Proxy = nil
				m.DNS.BaseDir = filepath.Join(dir, "not-a-directory")
				if err := os.WriteFile(m.DNS.BaseDir, nil, 0o600); err != nil {
					t.Fatal(err)
				}
				cfg.DNS.Enabled = true
			} else {
				m.DNS = nil
				m.Proxy.CertsDir = filepath.Join(dir, "missing-certs")
				cfg.Proxy.Reverse.Enabled = true
				cfg.Proxy.Reverse.Sites = []config.ReverseProxySite{{
					Name: "app", ListenPort: 443, TLSEnabled: true, CertRef: "missing",
					Backends: []string{"127.0.0.1:80"},
				}}
			}
			effective, warnings := m.ApplyEffective(context.Background(), cfg, nil)
			faults := m.Faults()
			if len(warnings) == 0 || len(faults) != 1 || faults[0].Service != service || faults[0].Kind != kind {
				t.Fatalf("fault outcome: %+v %v", faults, warnings)
			}
			if effective.DNS.Enabled || effective.Proxy.Reverse.Enabled || !m.DHCP.Current().Enabled {
				t.Fatal("fault did not quarantine only the failed service")
			}
			status := m.Status().(map[string]any)[service].(map[string]any)
			if status["state"] != "faulted" || testutil.ToFloat64(metrics.ServicesRunning.WithLabelValues(service)) != 0 ||
				testutil.ToFloat64(serviceFaulted.WithLabelValues(service)) != 1 {
				t.Fatalf("false healthy status: %+v", status)
			}
			// An identical replay must not emit another fault transition.
			m.ApplyEffective(context.Background(), cfg, nil)
			count := 0
			for _, ev := range m.ListTelemetryEvents(0) {
				if ev.Kind == "service."+kind+"_fault" {
					count++
				}
			}
			if count != 1 {
				t.Fatalf("repeated fault events: %d", count)
			}
		})
	}
}

type failingFaultAudit struct{ audit.Store }

func (failingFaultAudit) Add(context.Context, audit.Record) error { return errors.New("disk full") }

func TestManagerFaultChangesAndConcurrentStatus(t *testing.T) {
	m := NewManager(ManagerOptions{BaseDir: t.TempDir()})
	m.Syslog, m.DNS, m.NTP, m.Proxy, m.DHCP, m.VPN = nil, nil, nil, nil, nil, nil
	m.SetFaultAudit(failingFaultAudit{})
	faults := []config.ServiceConfigError{
		{Service: config.ServiceAV, Err: errors.New("bad scanner")},
		{Service: config.ServiceWireGuard, Err: errors.New("bad interface")},
		{Service: config.ServiceOpenVPN, Err: errors.New("bad profile")},
	}
	var wg sync.WaitGroup
	wg.Go(func() {
		for range 20 {
			m.ApplyEffective(context.Background(), config.ServicesConfig{}, faults)
		}
	})
	for range 20 {
		_ = m.Status()
		_ = m.Faults()
	}
	wg.Wait()
	status := m.Status().(map[string]any)
	for _, name := range []string{"av", "wireguard", "openvpn"} {
		if status[name].(map[string]any)["state"] != "faulted" {
			t.Fatalf("missing independent fault for %s: %+v", name, status)
		}
	}
	got := m.Faults()
	got[0].Message = "mutated"
	if m.Faults()[0].Message == "mutated" {
		t.Fatal("fault snapshot was not detached")
	}
	m.ApplyEffective(context.Background(), config.ServicesConfig{}, nil)
	if len(m.Faults()) != 0 {
		t.Fatal("successful apply retained obsolete fault")
	}
	for _, name := range []string{"av", "wireguard", "openvpn"} {
		if testutil.ToFloat64(serviceFaulted.WithLabelValues(name)) != 0 {
			t.Fatal("fault gauge not cleared")
		}
	}
}
