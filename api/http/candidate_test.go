// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

package httpapi

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/tonylturner/containd/pkg/cp/config"
	"github.com/tonylturner/containd/pkg/cp/templates"
	"github.com/tonylturner/containd/pkg/dp/learn"
	"github.com/tonylturner/containd/pkg/dp/pcap"
	"github.com/tonylturner/containd/pkg/dp/rules"
)

type stageEngine struct {
	*mockEngine
	mutations int
}

func (e *stageEngine) Configure(context.Context, config.DataPlaneConfig) error {
	e.mutations++
	return nil
}
func (e *stageEngine) ConfigureInterfaces(context.Context, []config.Interface) error {
	e.mutations++
	return nil
}
func (e *stageEngine) ConfigureRouting(context.Context, config.RoutingConfig) error {
	e.mutations++
	return nil
}
func (e *stageEngine) ConfigureServices(context.Context, config.ServicesConfig) ([]string, error) {
	e.mutations++
	return nil, nil
}
func (e *stageEngine) SetPcapConfig(_ context.Context, cfg config.PCAPConfig) (config.PCAPConfig, error) {
	e.mutations++
	return cfg, nil
}
func (e *stageEngine) StartPcap(context.Context, config.PCAPConfig) (pcap.Status, error) {
	e.mutations++
	return pcap.Status{}, nil
}
func (e *stageEngine) StopPcap(context.Context) (pcap.Status, error) {
	e.mutations++
	return pcap.Status{}, nil
}
func (e *stageEngine) ApplyRules(_ context.Context, snap rules.Snapshot) error {
	e.mutations++
	e.snap = snap
	return nil
}
func (e *stageEngine) ListLearnProfiles(context.Context) ([]learn.LearnedProfile, error) {
	return nil, nil
}
func (e *stageEngine) GenerateLearnRules(context.Context) ([]config.Rule, error) {
	return []config.Rule{{ID: "learned", Action: config.ActionAllow}}, nil
}
func (e *stageEngine) ClearLearnData(context.Context) error { return nil }

type stageServices struct{ mutations int }

func (s *stageServices) Apply(context.Context, config.ServicesConfig) error {
	s.mutations++
	return nil
}

func stageStore(t *testing.T) *config.SQLiteStore {
	t.Helper()
	store, err := config.NewSQLiteStore(filepath.Join(t.TempDir(), "config.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { store.Close() })
	cfg := config.DefaultConfig()
	cfg.System.Hostname = "running"
	cfg.Zones = append(cfg.Zones, config.Zone{Name: "spare"})
	cfg.Interfaces = append(cfg.Interfaces, config.Interface{Name: "spare", Zone: "lan"})
	cfg.Assets = []config.Asset{{ID: "old", Name: "old"}}
	cfg.Objects = []config.Object{{ID: "old", Name: "old", Type: config.ObjectType("HOST"), Addresses: []string{"10.0.0.1"}}}
	cfg.Firewall.Rules = []config.Rule{
		{ID: "old", Action: config.ActionAllow},
		{ID: "ics", Action: config.ActionAllow, ICS: config.ICSPredicate{Protocol: "modbus"}},
	}
	cfg.IDS.Rules = config.DefaultIDSConfig().Rules[:1]
	if err := store.Save(context.Background(), cfg); err != nil {
		t.Fatal(err)
	}
	return store
}

func jsonValue(t *testing.T, v any) any {
	t.Helper()
	data, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	var value any
	if err := json.Unmarshal(data, &value); err != nil {
		t.Fatal(err)
	}
	return value
}

func requestStage(t *testing.T, server http.Handler, method, path string, body any) *httptest.ResponseRecorder {
	t.Helper()
	data, err := json.Marshal(body)
	if err != nil {
		t.Fatal(err)
	}
	req := authedRequest(method, "/api/v1"+path, bytes.NewReader(data))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-User", "stage-tester")
	rec := httptest.NewRecorder()
	server.ServeHTTP(rec, req)
	return rec
}

func editableValue(cfg *config.Config, path string) any {
	switch path {
	case "/assets":
		return cfg.Assets
	case "/objects":
		return cfg.Objects
	case "/zones":
		return cfg.Zones
	case "/interfaces":
		return cfg.Interfaces
	case "/routing":
		return cfg.Routing
	case "/firewall/nat":
		return cfg.Firewall.NAT
	case "/dataplane":
		return cfg.DataPlane
	case "/ids/rules":
		return cfg.IDS
	case "/pcap/config":
		return cfg.PCAP
	case "/services/syslog":
		return cfg.Services.Syslog
	case "/services/dns":
		return cfg.Services.DNS
	case "/services/ntp":
		return cfg.Services.NTP
	case "/services/av":
		return cfg.Services.AV
	case "/services/dhcp":
		return cfg.Services.DHCP
	case "/services/proxy/forward":
		return cfg.Services.Proxy.Forward
	case "/services/proxy/reverse":
		return cfg.Services.Proxy.Reverse
	case "/services/vpn":
		return cfg.Services.VPN.RedactedVPNCopy()
	case "/firewall/ics-rules":
		var result []config.Rule
		for _, r := range cfg.Firewall.Rules {
			if hasICSPredicate(r) {
				result = append(result, r)
			}
		}
		return result
	default:
		return cfg.Firewall.Rules
	}
}

type candidateEndpointCase struct {
	method, path, list string
	body               any
}

func candidateEndpointCases() []candidateEndpointCase {
	defaults := config.DefaultConfig()
	return []candidateEndpointCase{
		{"POST", "/assets", "/assets", map[string]any{"id": "new", "name": "new"}},
		{"PATCH", "/assets/old", "/assets", map[string]any{"name": "edited"}},
		{"DELETE", "/assets/old", "/assets", nil},
		{"POST", "/objects", "/objects", map[string]any{"id": "new", "name": "new", "type": "HOST", "addresses": []string{"10.0.0.2"}}},
		{"PATCH", "/objects/old", "/objects", map[string]any{"description": "edited"}},
		{"DELETE", "/objects/old", "/objects", nil},
		{"POST", "/zones", "/zones", map[string]any{"name": "new"}},
		{"PATCH", "/zones/spare", "/zones", map[string]any{"description": "edited"}},
		{"DELETE", "/zones/spare", "/zones", nil},
		{"POST", "/interfaces", "/interfaces", map[string]any{"name": "new", "zone": "lan"}},
		{"PATCH", "/interfaces/spare", "/interfaces", map[string]any{"description": "edited"}},
		{"DELETE", "/interfaces/spare", "/interfaces", nil},
		{"POST", "/interfaces/assign", "/interfaces", map[string]any{"mode": "explicit", "mappings": map[string]string{"wan": "eth0"}}},
		{"POST", "/firewall/rules", "/firewall/rules", map[string]any{"id": "new", "action": "DENY"}},
		{"PATCH", "/firewall/rules/old", "/firewall/rules", map[string]any{"description": "edited"}},
		{"DELETE", "/firewall/rules/old", "/firewall/rules", nil},
		{"POST", "/firewall/ics-rules", "/firewall/ics-rules", map[string]any{"id": "new", "action": "DENY", "ics": map[string]string{"protocol": "modbus"}}},
		{"PATCH", "/firewall/ics-rules/ics", "/firewall/ics-rules", map[string]any{"action": "DENY", "ics": map[string]string{"protocol": "modbus"}}},
		{"POST", "/firewall/nat", "/firewall/nat", map[string]any{"snat": map[string]any{"enabled": true}}},
		{"POST", "/routing", "/routing", defaults.Routing},
		{"POST", "/dataplane", "/dataplane", defaults.DataPlane},
		{"POST", "/pcap/config", "/pcap/config", config.PCAPConfig{Interfaces: []string{"staged"}}},
		{"POST", "/ids/rules", "/ids/rules", config.IDSConfig{Enabled: true, Rules: config.DefaultIDSConfig().Rules[1:2]}},
		{"POST", "/ids/restore", "/ids/rules", config.DefaultIDSConfig().Rules[1:2]},
		{"POST", "/services/syslog", "/services/syslog", defaults.Services.Syslog},
		{"PATCH", "/services/syslog", "/services/syslog", map[string]string{"format": "json"}},
		{"POST", "/services/dns", "/services/dns", defaults.Services.DNS},
		{"POST", "/services/ntp", "/services/ntp", defaults.Services.NTP},
		{"POST", "/services/av", "/services/av", defaults.Services.AV},
		{"POST", "/services/dhcp", "/services/dhcp", defaults.Services.DHCP},
		{"POST", "/services/proxy/forward", "/services/proxy/forward", defaults.Services.Proxy.Forward},
		{"POST", "/services/proxy/reverse", "/services/proxy/reverse", defaults.Services.Proxy.Reverse},
		{"POST", "/services/vpn", "/services/vpn", defaults.Services.VPN},
		{"POST", "/services/vpn/openvpn/profile", "/services/vpn", map[string]string{"name": "staged", "ovpn": "client\nremote 192.0.2.1 1194\n"}},
		{"POST", "/templates/apply", "/firewall/rules", map[string]string{"name": templates.List()[0].Name}},
		{"POST", "/templates/ics/apply", "/firewall/rules", map[string]string{"template": "modbus_read_only"}},
		{"POST", "/learn/apply", "/firewall/rules", map[string]any{}},
	}
}

func TestConfigurationEndpointsStageWithoutApplying(t *testing.T) {
	for _, test := range candidateEndpointCases() {
		t.Run(test.method+test.path, func(t *testing.T) {
			t.Setenv("CONTAIND_OPENVPN_DIR", t.TempDir())
			store := stageStore(t)
			ctx := context.Background()
			running, _ := store.Load(ctx)
			if err := store.MutateCandidate(ctx, func(cfg *config.Config) error {
				cfg.System.Hostname = "unrelated-edit"
				return nil
			}); err != nil {
				t.Fatal(err)
			}
			engine := &stageEngine{mockEngine: &mockEngine{}}
			services := &stageServices{}
			audit := &mockAuditStore{}
			server := NewServerWithEngineAndServices(store, audit, engine, services, nil)
			rec := requestStage(t, server, test.method, test.path, test.body)
			wantStatus := http.StatusOK
			if test.method == http.MethodDelete {
				wantStatus = http.StatusNoContent
			}
			if rec.Code != wantStatus {
				t.Fatalf("status=%d body=%s", rec.Code, rec.Body)
			}
			assertConfigResponseHeader(t, rec, "staged")
			candidate, err := store.LoadCandidate(ctx)
			if err != nil || candidate.System.Hostname != "unrelated-edit" {
				t.Fatalf("lost candidate: %+v %v", candidate, err)
			}
			after, _ := store.Load(ctx)
			if !reflect.DeepEqual(running, after) || engine.mutations != 0 || services.mutations != 0 {
				t.Fatal("staging changed running or applied runtime state")
			}
			rec = requestStage(t, server, "GET", test.list, nil)
			assertConfigResponseHeader(t, rec, "")
			var got any
			if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil || !reflect.DeepEqual(got, jsonValue(t, editableValue(candidate, test.list))) {
				t.Fatalf("list did not return candidate: status=%d body=%s err=%v", rec.Code, rec.Body, err)
			}
			if len(audit.records) != 1 || audit.records[0].Actor != "stage-tester" || audit.records[0].Detail != "candidate" {
				t.Fatalf("want one actor/object/candidate audit, got %+v", audit.records)
			}
			rec = requestStage(t, server, "POST", "/config/commit", nil)
			assertConfigResponseHeader(t, rec, "committed")
			if rec.Code != http.StatusOK || engine.mutations == 0 || services.mutations != 1 {
				t.Fatalf("commit did not apply: %d %s", rec.Code, rec.Body)
			}
			committed, _ := store.Load(ctx)
			if !reflect.DeepEqual(jsonValue(t, committed), jsonValue(t, candidate)) {
				t.Fatal("commit did not promote candidate and IDS bank")
			}
			rec = requestStage(t, server, "POST", "/config/rollback", nil)
			assertConfigResponseHeader(t, rec, "committed")
			restored, _ := store.Load(ctx)
			if rec.Code != http.StatusOK || !reflect.DeepEqual(restored, running) {
				t.Fatalf("rollback did not restore config and bank: %d %s", rec.Code, rec.Body)
			}
		})
	}
}

func TestIDSSaveResponseSurvivesSecondSave(t *testing.T) {
	store := stageStore(t)
	engine := &stageEngine{mockEngine: &mockEngine{}}
	server := NewServerWithEngine(store, nil, engine)
	payload := config.IDSConfig{Enabled: true, Rules: config.DefaultIDSConfig().Rules[1:2]}
	for range 2 {
		rec := requestStage(t, server, "POST", "/ids/rules", payload)
		if rec.Code != http.StatusOK {
			t.Fatalf("%d %s", rec.Code, rec.Body)
		}
		if err := json.Unmarshal(rec.Body.Bytes(), &payload); err != nil || len(payload.Rules) != 1 {
			t.Fatalf("save response lost rules: %s %v", rec.Body, err)
		}
	}
	rec := requestStage(t, server, "POST", "/ids/rules", map[string]bool{"enabled": false})
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), payload.Rules[0].ID) {
		t.Fatalf("omitted rules erased bank: %d %s", rec.Code, rec.Body)
	}
	rec = httptest.NewRecorder()
	server.ServeHTTP(rec, idsApplyRequest(t, "import"))
	if rec.Code != http.StatusOK || engine.mutations != 0 {
		t.Fatalf("IDS import applied or failed: %d %s", rec.Code, rec.Body)
	}
	assertConfigResponseHeader(t, rec, "staged")
	cfg, _ := store.LoadCandidate(context.Background())
	if len(cfg.IDS.Rules) != 2 {
		t.Fatalf("IDS import lost candidate bank: %+v", cfg.IDS.Rules)
	}
}

func TestVPNProfileUploadsNeverOverwriteRunningArtifact(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("CONTAIND_OPENVPN_DIR", dir)
	store := stageStore(t)
	server := NewServer(store, nil)
	upload := func(content string) string {
		rec := requestStage(t, server, "POST", "/services/vpn/openvpn/profile", map[string]string{"name": "same", "ovpn": content})
		if rec.Code != http.StatusOK {
			t.Fatalf("%d %s", rec.Code, rec.Body)
		}
		cfg, _ := store.LoadCandidate(context.Background())
		return cfg.Services.VPN.OpenVPN.ConfigPath
	}
	first := upload("client\nremote first 1194\n")
	if err := store.Commit(context.Background()); err != nil {
		t.Fatal(err)
	}
	second := upload("client\nremote second 1194\n")
	third := upload("client\nremote third 1194\n")
	data, err := os.ReadFile(first)
	if err != nil || first == second || second == third || !strings.Contains(string(data), "first") {
		t.Fatalf("profile overwritten: %q %q %q %s %v", first, second, third, data, err)
	}
}
