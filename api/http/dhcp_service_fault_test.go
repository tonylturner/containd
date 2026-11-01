// SPDX-License-Identifier: Apache-2.0
package httpapi

import (
	"context"
	"database/sql"
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/tonylturner/containd/pkg/cp/config"
	"github.com/tonylturner/containd/pkg/cp/services"
	"github.com/tonylturner/containd/pkg/dp/rules"
)

// storedDHCPListenStore installs historical content behind write validation,
// then reopens the store as a management restart would.
func storedDHCPListenStore(t *testing.T, listenName string) *config.SQLiteStore {
	t.Helper()
	path := filepath.Join(t.TempDir(), "config.db")
	store, err := config.NewSQLiteStore(path)
	if err != nil {
		t.Fatal(err)
	}
	cfg := config.DefaultConfig()
	cfg.Interfaces = nil
	cfg.DataPlane.Enforcement = true
	cfg.Firewall.DefaultAction = config.ActionAllow
	cfg.Services.NTP = config.NTPConfig{Enabled: true, Servers: []string{"192.0.2.123"}}
	if err := store.Save(context.Background(), cfg); err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	cfg.Services.DHCP = config.DHCPConfig{Enabled: true, ListenIfaces: []string{listenName}}
	body, err := json.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if _, err := db.Exec(`UPDATE configs SET data = ? WHERE key = 'running'`, string(body)); err != nil {
		t.Fatal(err)
	}
	store, err = config.NewSQLiteStore(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { store.Close() })
	return store
}

func TestDHCPListenFaultReplayAndStatus(t *testing.T) {
	store := storedDHCPListenStore(t, "bad/iface")
	baseDir := t.TempDir()
	manager := services.NewManager(services.ManagerOptions{BaseDir: baseDir})
	manager.Syslog, manager.DNS, manager.Proxy, manager.VPN = nil, nil, nil, nil
	manager.NTP.Supervise = false
	manager.NTP.NTPDPath = ""
	for _, replay := range []struct {
		name  string
		apply func(context.Context, config.Store, EngineClient, ServicesApplier) ([]string, error)
	}{
		{"boot", ApplyBootConfig},
		{"reconnect", ApplyRunningConfig},
	} {
		t.Run(replay.name, func(t *testing.T) {
			engine := &mockEngine{}
			warnings, err := replay.apply(context.Background(), store, engine, manager)
			if err != nil || !engine.applied || engine.snap.Default != rules.ActionAllow || !engine.lastDP.Enforcement {
				t.Fatalf("DHCP fault blocked stored firewall replay: %v %v", err, warnings)
			}
			if !slices.Contains(warnings, "dhcp: quarantined") || engine.lastSvc.DHCP.Enabled || manager.DHCP.Current().Enabled {
				t.Fatalf("DHCP was not quarantined: %+v %v", engine.lastSvc.DHCP, warnings)
			}
			if !engine.lastSvc.NTP.Enabled || !manager.NTP.Current().Enabled {
				t.Fatal("DHCP quarantine disabled another service")
			}
			rendered, err := os.ReadFile(filepath.Join(baseDir, "chrony.conf"))
			if err != nil || !strings.Contains(string(rendered), "server 192.0.2.123 iburst") {
				t.Fatalf("other service was not applied: %v %s", err, rendered)
			}
			server := NewServerWithEngineAndServices(store, nil, engine, manager, newMockUserStore())
			rec := requestStage(t, server, http.MethodGet, "/services/status", nil)
			var out struct {
				Faults []services.ServiceFault `json:"faults"`
				DHCP   struct {
					State string                `json:"state"`
					Fault services.ServiceFault `json:"fault"`
				} `json:"dhcp"`
			}
			if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
				t.Fatal(err)
			}
			if rec.Code != http.StatusOK || len(out.Faults) != 1 || out.Faults[0].Service != config.ServiceDHCP ||
				out.Faults[0].Kind != "config" || out.Faults[0].Message == "" || out.DHCP.State != "faulted" || out.DHCP.Fault != out.Faults[0] {
				t.Fatalf("status lost DHCP configuration fault: %d %s", rec.Code, rec.Body)
			}
			desired, err := store.Load(context.Background())
			if err != nil || !desired.Services.DHCP.Enabled || !slices.Equal(desired.Services.DHCP.ListenIfaces, []string{"bad/iface"}) {
				t.Fatalf("replay changed desired DHCP config: %v %+v", err, desired)
			}
		})
	}
}

func TestDHCPListenNameWriteValidation(t *testing.T) {
	for _, tc := range []struct {
		name, storedName, nextName string
		unrelated                  bool
		wantStatus                 int
	}{
		{"new fault", "fixture0", "bad/iface", false, http.StatusBadRequest},
		{"changed fault", "bad/iface", "bad:iface", false, http.StatusBadRequest},
		{"carried fault", "bad/iface", "bad/iface", true, http.StatusOK},
		{"unconfigured kernel device", "fixture0", "other0", false, http.StatusOK},
	} {
		t.Run(tc.name, func(t *testing.T) {
			store := storedDHCPListenStore(t, tc.storedName)
			ctx := context.Background()
			beforeSnapshot, err := store.ReadSnapshot(ctx, config.SnapshotCandidate, true)
			before := beforeSnapshot.Candidate
			if err != nil {
				t.Fatal(err)
			}
			engine := &mockEngine{}
			server := NewServerWithEngine(store, nil, engine)
			path := "/services/dhcp"
			var body any = config.DHCPConfig{Enabled: true, ListenIfaces: []string{tc.nextName}}
			if tc.unrelated {
				nextSnapshot, err := store.ReadSnapshot(ctx, config.SnapshotCandidate, true)
				next := nextSnapshot.Candidate
				if err != nil {
					t.Fatal(err)
				}
				next.Description = "unrelated firewall repair"
				path, body = "/config", next
			}
			rec := requestStage(t, server, http.MethodPost, path, body)
			if rec.Code != tc.wantStatus || engine.applied {
				t.Fatalf("write status: %d %s", rec.Code, rec.Body)
			}
			afterSnapshot, err := store.ReadSnapshot(ctx, config.SnapshotCandidate, true)
			after := afterSnapshot.Candidate
			if err != nil {
				t.Fatal(err)
			}
			if tc.wantStatus == http.StatusBadRequest {
				if !strings.Contains(rec.Body.String(), "dhcp listenIfaces") || !reflect.DeepEqual(before, after) {
					t.Fatalf("rejected write lost fault or changed candidate: %s", rec.Body)
				}
				return
			}
			assertConfigResponseHeader(t, rec, "staged")
			if !slices.Equal(after.Services.DHCP.ListenIfaces, []string{tc.nextName}) {
				t.Fatal("accepted write changed DHCP listen interfaces")
			}
			if tc.unrelated {
				rec = requestStage(t, server, http.MethodPost, "/config/commit", nil)
				running, err := store.Load(ctx)
				if rec.Code != http.StatusOK || err != nil || running.Description != after.Description ||
					!reflect.DeepEqual(running.Services.DHCP, before.Services.DHCP) || !engine.applied || engine.lastSvc.DHCP.Enabled {
					t.Fatalf("carried DHCP fault blocked commit or lost desired state: %d %s %v", rec.Code, rec.Body, err)
				}
			}
		})
	}
}
