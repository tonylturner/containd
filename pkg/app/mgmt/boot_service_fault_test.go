// SPDX-License-Identifier: Apache-2.0
package mgmtapp

import (
	"errors"
	"fmt"
	"net/netip"
	"strings"
	"testing"

	"github.com/tonylturner/containd/pkg/common/mgmtpath"
	"github.com/tonylturner/containd/pkg/cp/config"
	"go.uber.org/zap"
)

func TestBootServiceFaultDecision(t *testing.T) {
	for _, reserved := range []bool{false, true} {
		for _, mode := range []string{"clean", "service-only", "mixed", "mixed-late-scan"} {
			t.Run(fmt.Sprintf("%t/%s", reserved, mode), func(t *testing.T) {
				cfg := config.DefaultConfig()
				var reservation *mgmtpath.Reservation
				if reserved {
					reservation = &mgmtpath.Reservation{
						Device: "fixture", Local: netip.MustParsePrefix("10.99.99.2/24"), Port: 8080,
					}
					cfg.Interfaces = []config.Interface{{Name: "custom", Device: reservation.Device, Zone: "lan"}}
					cfg.DataPlane.Enforcement = true
				}
				if mode != "clean" {
					cfg.Services.DNS.UpstreamServers = []string{"1.1.1.1\nserver:"}
					cfg.Services.Proxy.Forward.Upstream = "legacy-upstream"
					cfg.Services.Proxy.Forward.ListenZones = []string{"bad\nzone"}
					cfg.Services.VPN.OpenVPN.Managed = &config.OpenVPNManagedClientConfig{Password: "private-secret\ninjected"}
				}
				if mode == "mixed" {
					cfg.Firewall.DefaultAction = "invalid"
				}
				if mode == "mixed-late-scan" {
					cfg.Services.AV.Scan.DownloadMode = "invalid"
				}
				mixed := strings.HasPrefix(mode, "mixed")
				if err := bootConflict(cfg, reservation); (err != nil) != mixed {
					t.Fatalf("conflict=%v, want mixed=%t", err, mixed)
				}
				store := &bootFaultRecordingStore{fault: "historical recovery"}
				auditStore := &testAuditStore{}
				event, err := recordBootDecision(zap.NewNop().Sugar(), mgmtStores{
					store: store, auditStore: auditStore,
				}, cfg, reservation)
				if err != nil {
					t.Fatal(err)
				}
				if (store.fault != "") != mixed || store.calls != 1 {
					t.Fatalf("wrong management recovery decision: %+v", store)
				}
				if mode == "clean" {
					if event != nil || len(auditStore.records) != 0 {
						t.Fatalf("clean boot has fault evidence: %+v %+v", event, auditStore.records)
					}
					return
				}
				if mixed && !strings.Contains(event.Kind, "boot_fault") {
					t.Fatalf("lost primary management boot fault: %+v", event)
				}
				services := &bootEventServices{event: event}
				events := services.ListTelemetryEvents(0)
				want := 3
				if mixed {
					want++
				}
				if len(events) != want || len(auditStore.records) != want {
					t.Fatalf("fault evidence count: events=%+v audit=%+v", events, auditStore.records)
				}
				seen := map[string]bool{}
				for _, e := range events {
					if e.Kind != "service.config_fault" {
						continue
					}
					service, _ := e.Attributes["service"].(string)
					detail, _ := e.Attributes["error"].(string)
					if seen[service] || service == "" || detail == "" || strings.ContainsAny(detail, "\r\n\x00") || strings.Contains(detail, "private-secret") {
						t.Fatalf("invalid service evidence: %+v", e)
					}
					seen[service] = true
				}
				for _, service := range []string{config.ServiceDNS, config.ServiceProxy, config.ServiceOpenVPN} {
					if !seen[service] {
						t.Errorf("missing service fault for %s", service)
					}
				}
				for _, r := range auditStore.records {
					if r.Action == "service.config_fault" && (r.Target == "" || strings.ContainsAny(r.Detail, "\r\n\x00") || strings.Contains(r.Detail, "private-secret")) {
						t.Fatalf("unsafe service audit record: %+v", r)
					}
				}
				if got := services.ListTelemetryEvents(1); len(got) != 1 {
					t.Fatalf("telemetry limit ignored: %+v", got)
				}
			})
		}
	}
}

func TestBootServiceFaultErrorTree(t *testing.T) {
	fault := &config.ServiceConfigError{Service: config.ServiceDNS, Err: errors.New("bad forwarder")}
	wrapped := fmt.Errorf("validation: %w", fault)
	other := errors.New("firewall fault")
	for _, tc := range []struct {
		err   error
		count int
		mixed bool
	}{
		{nil, 0, false},
		{wrapped, 1, false},
		{errors.Join(fault, wrapped), 2, false},
		{errors.Join(fault, other), 1, true},
		{fmt.Errorf("outer: %w", errors.Join(fault, other)), 1, true},
	} {
		faults, err := splitServiceFaults(tc.err)
		if len(faults) != tc.count || (err != nil) != tc.mixed {
			t.Errorf("split %v => faults=%v other=%v", tc.err, faults, err)
		}
	}
}
