// SPDX-License-Identifier: Apache-2.0
package engineapp

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	engineapi "github.com/tonylturner/containd/api/engine"
	httpapi "github.com/tonylturner/containd/api/http"
	"github.com/tonylturner/containd/pkg/cp/config"
	"github.com/tonylturner/containd/pkg/cp/services"
	"github.com/tonylturner/containd/pkg/dp/rules"
	"go.uber.org/zap"
)

type runtimeDHCPApplier struct {
	calls atomic.Int32
	fail  *atomic.Bool
}

func (a *runtimeDHCPApplier) Apply(context.Context, config.DHCPConfig, []config.Interface) error {
	a.calls.Add(1)
	if a.fail.Load() {
		return errors.New("DHCP backend refused secret-material")
	}
	return nil
}

type runtimeAVApplier struct{ calls atomic.Int32 }

func (a *runtimeAVApplier) Apply(context.Context, config.AVConfig) error {
	a.calls.Add(1)
	return nil
}

func TestServiceRuntimeFaultReplay(t *testing.T) {
	for _, service := range []string{config.ServiceWireGuard, config.ServiceDHCP} {
		t.Run(service, func(t *testing.T) {
			ctx := context.Background()
			store, err := config.NewSQLiteStore(filepath.Join(t.TempDir(), "config.db"))
			if err != nil {
				t.Fatal(err)
			}
			defer store.Close()
			cfg := config.DefaultConfig()
			cfg.Interfaces = []config.Interface{{Name: "test0", Device: "ct-test0", Zone: "lan", Addresses: []string{"198.51.100.1/24"}}}
			cfg.Services.VPN.WireGuard = config.WireGuardConfig{
				Enabled: true, Interface: "ct-vpn", ListenPort: 51820,
				PrivateKey: "ERERERERERERERERERERERERERERERERERERERERERE=",
			}
			cfg.Services.DHCP = config.DHCPConfig{
				Enabled: true, ListenIfaces: []string{"test0"},
				Pools: []config.DHCPPool{{Iface: "test0", Start: "198.51.100.100", End: "198.51.100.150"}},
			}
			cfg.Services.AV.Enabled = true
			if err := store.Save(ctx, cfg); err != nil {
				t.Fatal(err)
			}
			m := services.NewManager(services.ManagerOptions{BaseDir: t.TempDir()})
			m.Syslog, m.DNS, m.NTP, m.Proxy, m.VPN = nil, nil, nil, nil, nil
			var failWG, failDHCP, requestFailure atomic.Bool
			failWG.Store(service == config.ServiceWireGuard)
			failDHCP.Store(service == config.ServiceDHCP)
			dhcp := &runtimeDHCPApplier{fail: &failDHCP}
			av := &runtimeAVApplier{}
			var wgCalls, rulesCalls atomic.Int32
			applyWG := func(context.Context, config.WireGuardConfig) error {
				wgCalls.Add(1)
				if failWG.Load() {
					return errors.New("WireGuard backend refused secret-material")
				}
				return nil
			}
			handler := serviceApplyHandler(zap.NewNop().Sugar(), nil, nil, dhcp, av, nil, applyWG)
			mux := http.NewServeMux()
			mux.HandleFunc("/internal/services", func(w http.ResponseWriter, r *http.Request) {
				if requestFailure.Load() {
					if _, err := io.Copy(io.Discard, r.Body); err != nil {
						t.Error(err)
					}
					http.Error(w, "request refused", http.StatusServiceUnavailable)
					return
				}
				handler.ServeHTTP(w, r)
			})
			mux.HandleFunc("/internal/apply_rules", func(w http.ResponseWriter, r *http.Request) {
				var snap rules.Snapshot
				if err := json.NewDecoder(r.Body).Decode(&snap); err != nil {
					t.Error(err)
				}
				rulesCalls.Add(1)
				_, _ = w.Write([]byte(`{}`))
			})
			mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
				if _, err := io.Copy(io.Discard, r.Body); err != nil {
					t.Error(err)
				}
				_, _ = w.Write([]byte(`{}`))
			})
			server := httptest.NewServer(mux)
			defer server.Close()
			client := engineapi.NewHTTPClient(server.URL)
			for i := range 4 {
				if i == 2 {
					requestFailure.Store(true)
				}
				if i == 3 {
					requestFailure.Store(false)
					failWG.Store(false)
					failDHCP.Store(false)
				}
				warnings, err := httpapi.ApplyRunningConfig(ctx, store, client, m)
				serviceCalls := int32(i + 1)
				if i >= 2 {
					serviceCalls--
				}
				if err != nil || wgCalls.Load() != serviceCalls || dhcp.calls.Load() != serviceCalls || av.calls.Load() != serviceCalls || rulesCalls.Load() != int32(i+1) {
					t.Fatalf("failure prevented another apply: wg=%d dhcp=%d rules=%d err=%v", wgCalls.Load(), dhcp.calls.Load(), rulesCalls.Load(), err)
				}
				faults := m.Faults()
				status := m.Status().(map[string]any)[service].(map[string]any)
				if i < 3 {
					if len(faults) != 1 || faults[0].Service != service || faults[0].Kind != "runtime" {
						t.Fatalf("fault attributed incorrectly: %+v", faults)
					}
					if status["state"] != "faulted" || status["fault"] != faults[0] {
						t.Fatalf("runtime service status lost fault: %+v", status)
					}
					wantWarning := service + ": runtime apply failed"
					if i == 2 {
						wantWarning = "engine services status 503"
					}
					if !strings.Contains(strings.Join(warnings, ","), wantWarning) ||
						strings.Contains(strings.Join(warnings, ","), "secret-material") {
						t.Fatalf("missing or unsanitized warning: %v", warnings)
					}
				} else if len(faults) != 0 {
					t.Fatalf("clean apply did not clear runtime fault: %+v", faults)
				} else if status["state"] == "faulted" {
					t.Fatalf("clean apply retained faulted status: %+v", status)
				}
			}
			raised, cleared := 0, 0
			for _, event := range m.ListTelemetryEvents(0) {
				switch event.Kind {
				case "service.runtime_fault":
					raised++
				case "service.runtime_fault.cleared":
					cleared++
				}
			}
			if raised != 1 || cleared != 1 {
				t.Fatalf("fault replay emitted duplicate transitions: raised=%d cleared=%d", raised, cleared)
			}
		})
	}
}
