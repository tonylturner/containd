// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

package httpapi

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/tonylturner/containd/pkg/cp/config"
)

func TestApplyICSTemplatePreviewDoesNotSave(t *testing.T) {
	store := &mockStore{cfg: config.DefaultConfig()}
	s := NewServer(store, nil)
	rec := httptest.NewRecorder()
	req := authedRequest(http.MethodPost, "/api/v1/templates/ics/apply", bytes.NewBufferString(`{
		"template":"modbus_register_guard",
		"sourceZones":["lan"],
		"destZones":["wan"],
		"parameters":{"ranges":"0-99,400-499"},
		"preview":true
	}`))
	req.Header.Set("Content-Type", "application/json")
	s.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d body=%s", rec.Code, rec.Body.String())
	}
	if store.calls != 0 {
		t.Fatalf("preview should not save config, save calls=%d", store.calls)
	}
	var resp struct {
		Preview bool          `json:"preview"`
		Rules   []config.Rule `json:"rules"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if !resp.Preview {
		t.Fatal("expected preview response")
	}
	if len(resp.Rules) != 1 {
		t.Fatalf("expected 1 generated rule, got %d", len(resp.Rules))
	}
	rule := resp.Rules[0]
	if got := strings.Join(rule.ICS.Addresses, ","); got != "0-99,400-499" {
		t.Fatalf("unexpected ranges %q", got)
	}
	if got := strings.Join(rule.SourceZones, ","); got != "lan" {
		t.Fatalf("unexpected source zones %q", got)
	}
	if got := strings.Join(rule.DestZones, ","); got != "wan" {
		t.Fatalf("unexpected dest zones %q", got)
	}
}

func TestApplyICSTemplatePersistsRules(t *testing.T) {
	store := &mockStore{cfg: config.DefaultConfig()}
	beforeCount := len(store.cfg.Firewall.Rules)
	s := NewServer(store, nil)
	rec := httptest.NewRecorder()
	req := authedRequest(http.MethodPost, "/api/v1/templates/ics/apply", bytes.NewBufferString(`{
		"template":"modbus_read_only",
		"sourceZones":["lan"],
		"destZones":["wan"]
	}`))
	req.Header.Set("Content-Type", "application/json")
	s.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d body=%s", rec.Code, rec.Body.String())
	}
	if store.cfg == nil {
		t.Fatal("expected config to be saved")
	}
	if len(store.cfg.Firewall.Rules) != beforeCount+2 {
		t.Fatalf("expected 2 new persisted rules, got before=%d after=%d", beforeCount, len(store.cfg.Firewall.Rules))
	}
	foundAllow := false
	foundDeny := false
	for _, rule := range store.cfg.Firewall.Rules {
		switch rule.ID {
		case "tpl-modbus-allow-reads":
			foundAllow = true
		case "tpl-modbus-deny-writes":
			foundDeny = true
		default:
			continue
		}
		if got := strings.Join(rule.SourceZones, ","); got != "lan" {
			t.Fatalf("unexpected source zones %q for rule %s", got, rule.ID)
		}
		if got := strings.Join(rule.DestZones, ","); got != "wan" {
			t.Fatalf("unexpected dest zones %q for rule %s", got, rule.ID)
		}
	}
	if !foundAllow || !foundDeny {
		t.Fatalf("expected template rules to be persisted, got %+v", store.cfg.Firewall.Rules)
	}
	var resp struct {
		Applied bool          `json:"applied"`
		Created int           `json:"created"`
		Updated int           `json:"updated"`
		Rules   []config.Rule `json:"rules"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if !resp.Applied || resp.Created != 2 || resp.Updated != 0 || len(resp.Rules) != 2 {
		t.Fatalf("unexpected response %+v", resp)
	}
}

func TestApplyICSTemplateListFirewallRulesReturnsArraySafeShapes(t *testing.T) {
	store := &mockStore{cfg: config.DefaultConfig()}
	s := NewServer(store, nil)

	rec := httptest.NewRecorder()
	req := authedRequest(http.MethodPost, "/api/v1/templates/ics/apply", bytes.NewBufferString(`{
		"template":"modbus_read_only",
		"sourceZones":["lan"],
		"destZones":["wan"]
	}`))
	req.Header.Set("Content-Type", "application/json")
	s.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("apply template: expected 200, got %d body=%s", rec.Code, rec.Body.String())
	}

	rec = httptest.NewRecorder()
	req = authedRequest(http.MethodGet, "/api/v1/firewall/rules", nil)
	s.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("list firewall rules: expected 200, got %d body=%s", rec.Code, rec.Body.String())
	}

	var payload []map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &payload); err != nil {
		t.Fatalf("decode firewall rules payload: %v", err)
	}

	for _, rule := range payload {
		if id, _ := rule["id"].(string); id != "tpl-modbus-allow-reads" && id != "tpl-modbus-deny-writes" {
			continue
		}
		if _, ok := rule["sourceZones"].([]any); !ok {
			t.Fatalf("sourceZones must be a JSON array for rule %v: %#v", rule["id"], rule["sourceZones"])
		}
		if _, ok := rule["destZones"].([]any); !ok {
			t.Fatalf("destZones must be a JSON array for rule %v: %#v", rule["id"], rule["destZones"])
		}
		if _, ok := rule["protocols"].([]any); !ok {
			t.Fatalf("protocols must be a JSON array for rule %v: %#v", rule["id"], rule["protocols"])
		}
		rawICS, ok := rule["ics"].(map[string]any)
		if !ok {
			t.Fatalf("ics must be an object for rule %v: %#v", rule["id"], rule["ics"])
		}
		if fc, ok := rawICS["functionCode"]; ok {
			if _, ok := fc.([]any); !ok {
				t.Fatalf("ics.functionCode must be a JSON array for rule %v: %#v", rule["id"], fc)
			}
		}
		if addrs, ok := rawICS["addresses"]; ok {
			if _, ok := addrs.([]any); !ok {
				t.Fatalf("ics.addresses must be a JSON array for rule %v: %#v", rule["id"], addrs)
			}
		}
	}
}

func TestApplyICSTemplateUpsertsExistingRules(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.Firewall.Rules = []config.Rule{{
		ID:          "tpl-modbus-register-allow",
		Description: "old",
		SourceZones: []string{"old-src"},
		DestZones:   []string{"old-dst"},
		Protocols:   []config.Protocol{{Name: "tcp", Port: "502"}},
		ICS: config.ICSPredicate{
			Protocol:  "modbus",
			Addresses: []string{"1-9"},
		},
		Action: config.ActionAllow,
	}}
	store := &mockStore{cfg: cfg}
	s := NewServer(store, nil)
	rec := httptest.NewRecorder()
	req := authedRequest(http.MethodPost, "/api/v1/templates/ics/apply", bytes.NewBufferString(`{
		"template":"modbus_register_guard",
		"sourceZones":["lan"],
		"destZones":["wan"],
		"parameters":{"ranges":"100-199"}
	}`))
	req.Header.Set("Content-Type", "application/json")
	s.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d body=%s", rec.Code, rec.Body.String())
	}
	if len(store.cfg.Firewall.Rules) != 1 {
		t.Fatalf("expected upsert to keep 1 rule, got %d", len(store.cfg.Firewall.Rules))
	}
	rule := store.cfg.Firewall.Rules[0]
	if got := strings.Join(rule.ICS.Addresses, ","); got != "100-199" {
		t.Fatalf("expected updated ranges, got %q", got)
	}
	if got := strings.Join(rule.SourceZones, ","); got != "lan" {
		t.Fatalf("expected updated source zones, got %q", got)
	}
	if got := strings.Join(rule.DestZones, ","); got != "wan" {
		t.Fatalf("expected updated dest zones, got %q", got)
	}
}

func TestAssignInterfacesAuto(t *testing.T) {
	m := &mockStore{}
	eng := &mockEngine{
		state: []config.InterfaceState{
			{Name: "lo", Index: 1, Up: true},
			{Name: "eth0", Index: 2, Up: true},
			{Name: "eth1", Index: 3, Up: true},
			{Name: "eth2", Index: 4, Up: true},
			{Name: "eth3", Index: 5, Up: true},
			{Name: "eth4", Index: 6, Up: true},
			{Name: "eth5", Index: 7, Up: true},
			{Name: "eth6", Index: 8, Up: true},
			{Name: "eth7", Index: 9, Up: true},
		},
	}
	s := NewServerWithEngine(m, nil, eng)
	rec := httptest.NewRecorder()
	req := authedRequest(http.MethodPost, "/api/v1/interfaces/assign", bytes.NewBufferString(`{"mode":"auto"}`))
	req.Header.Set("Content-Type", "application/json")
	s.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d body=%s", rec.Code, rec.Body.String())
	}
	if len(eng.lastIf) == 0 {
		t.Fatalf("expected interfaces applied to engine")
	}
	foundWAN := false
	for _, iface := range eng.lastIf {
		if iface.Name == "wan" {
			foundWAN = true
			if iface.Device != "eth0" {
				t.Fatalf("expected wan device eth0, got %q", iface.Device)
			}
		}
	}
	if !foundWAN {
		t.Fatalf("expected wan interface in engine config")
	}
}

func TestAssignInterfacesAutoPrefersSubnetMatching(t *testing.T) {
	m := &mockStore{}
	eng := &mockEngine{
		state: []config.InterfaceState{
			{Name: "lo", Index: 1, Up: true},
			{Name: "eth0", Index: 2, Up: true, Addrs: []string{"192.168.245.2/24"}},
			{Name: "eth1", Index: 3, Up: true, Addrs: []string{"192.168.240.2/24"}},
			{Name: "eth2", Index: 4, Up: true, Addrs: []string{"192.168.241.2/24"}},
			{Name: "eth3", Index: 5, Up: true, Addrs: []string{"192.168.242.2/24"}},
			{Name: "eth4", Index: 6, Up: true, Addrs: []string{"192.168.243.2/24"}},
			{Name: "eth5", Index: 7, Up: true, Addrs: []string{"192.168.244.2/24"}},
			{Name: "eth6", Index: 8, Up: true, Addrs: []string{"192.168.246.2/24"}},
			{Name: "eth7", Index: 9, Up: true, Addrs: []string{"192.168.247.2/24"}},
		},
	}
	s := NewServerWithEngine(m, nil, eng)
	rec := httptest.NewRecorder()
	req := authedRequest(http.MethodPost, "/api/v1/interfaces/assign", bytes.NewBufferString(`{"mode":"auto"}`))
	req.Header.Set("Content-Type", "application/json")
	s.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d body=%s", rec.Code, rec.Body.String())
	}

	got := map[string]string{}
	for _, iface := range eng.lastIf {
		if iface.Name == "" || iface.Device == "" {
			continue
		}
		got[iface.Name] = iface.Device
	}
	if got["wan"] != "eth1" {
		t.Fatalf("expected wan device eth1 (subnet match), got %q", got["wan"])
	}
	if got["dmz"] != "eth2" {
		t.Fatalf("expected dmz device eth2 (subnet match), got %q", got["dmz"])
	}
	if got["lan4"] != "eth0" {
		t.Fatalf("expected lan4 device eth0 (subnet match), got %q", got["lan4"])
	}
}

func TestAssignInterfacesRejectsDuplicateDevice(t *testing.T) {
	m := &mockStore{}
	eng := &mockEngine{
		state: []config.InterfaceState{
			{Name: "eth0", Index: 2, Up: true},
			{Name: "eth1", Index: 3, Up: true},
			{Name: "eth2", Index: 4, Up: true},
			{Name: "eth3", Index: 5, Up: true},
			{Name: "eth4", Index: 6, Up: true},
			{Name: "eth5", Index: 7, Up: true},
			{Name: "eth6", Index: 8, Up: true},
			{Name: "eth7", Index: 9, Up: true},
		},
	}
	s := NewServerWithEngine(m, nil, eng)
	rec := httptest.NewRecorder()
	req := authedRequest(http.MethodPost, "/api/v1/interfaces/assign", bytes.NewBufferString(`{"mode":"explicit","mappings":{"wan":"eth0","dmz":"eth0"}}`))
	req.Header.Set("Content-Type", "application/json")
	s.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d body=%s", rec.Code, rec.Body.String())
	}
}

func TestDefaultInterfacesSeeded(t *testing.T) {
	m := &mockStore{}
	m.load = func() (*config.Config, error) { return nil, config.ErrNotFound }
	s := NewServer(m, nil)
	rec := httptest.NewRecorder()
	req := authedRequest(http.MethodGet, "/api/v1/interfaces", nil)
	s.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}
	if !bytes.Contains(rec.Body.Bytes(), []byte(`"wan"`)) || !bytes.Contains(rec.Body.Bytes(), []byte(`"lan6"`)) {
		t.Fatalf("expected default interfaces in response, got %s", rec.Body.String())
	}
}

func TestAutoBindDefaultInterfaceDevicesFromStateUsesSubnetMapping(t *testing.T) {
	cfg := config.DefaultConfig()
	state := []config.InterfaceState{
		{Name: "lo", Index: 1, Up: true},
		{Name: "eth0", Index: 2, Up: true, MAC: "02:00:00:00:00:10", Addrs: []string{"192.168.245.2/24"}},
		{Name: "eth1", Index: 3, Up: true, MAC: "02:00:00:00:00:11", Addrs: []string{"192.168.240.2/24"}},
		{Name: "eth2", Index: 4, Up: true, MAC: "02:00:00:00:00:12", Addrs: []string{"192.168.241.2/24"}},
		{Name: "eth3", Index: 5, Up: true, MAC: "02:00:00:00:00:13", Addrs: []string{"192.168.242.2/24"}},
		{Name: "eth4", Index: 6, Up: true, MAC: "02:00:00:00:00:14", Addrs: []string{"192.168.243.2/24"}},
		{Name: "eth5", Index: 7, Up: true, MAC: "02:00:00:00:00:15", Addrs: []string{"192.168.244.2/24"}},
		{Name: "eth6", Index: 8, Up: true, MAC: "02:00:00:00:00:16", Addrs: []string{"192.168.246.2/24"}},
		{Name: "eth7", Index: 9, Up: true, MAC: "02:00:00:00:00:17", Addrs: []string{"192.168.247.2/24"}},
	}

	if !autoBindDefaultInterfaceDevicesFromState(cfg, state, "eth1") {
		t.Fatalf("expected safe default bindings to be applied")
	}

	got := map[string]string{}
	for _, iface := range cfg.Interfaces {
		got[iface.Name] = iface.Device
	}
	if got["wan"] != "eth1" {
		t.Fatalf("expected wan to bind to eth1, got %q", got["wan"])
	}
	if got["dmz"] != "eth2" {
		t.Fatalf("expected dmz to bind to eth2, got %q", got["dmz"])
	}
	if got["lan4"] != "eth0" {
		t.Fatalf("expected lan4 to bind to eth0, got %q", got["lan4"])
	}
}

func TestAutoBindDefaultInterfaceDevicesFromStateRepairsLegacyIndexBinding(t *testing.T) {
	cfg := config.DefaultConfig()
	for i := range cfg.Interfaces {
		cfg.Interfaces[i].Device = fmt.Sprintf("eth%d", i)
	}
	state := []config.InterfaceState{
		{Name: "lo", Index: 1, Up: true},
		{Name: "eth0", Index: 2, Up: true, MAC: "02:00:00:00:00:10", Addrs: []string{"192.168.245.2/24"}},
		{Name: "eth1", Index: 3, Up: true, MAC: "02:00:00:00:00:11", Addrs: []string{"192.168.246.2/24"}},
		{Name: "eth2", Index: 4, Up: true, MAC: "02:00:00:00:00:12", Addrs: []string{"192.168.247.2/24"}},
		{Name: "eth3", Index: 5, Up: true, MAC: "02:00:00:00:00:13", Addrs: []string{"192.168.240.2/24"}},
		{Name: "eth4", Index: 6, Up: true, MAC: "02:00:00:00:00:14", Addrs: []string{"192.168.241.2/24"}},
		{Name: "eth5", Index: 7, Up: true, MAC: "02:00:00:00:00:15", Addrs: []string{"192.168.242.2/24"}},
		{Name: "eth6", Index: 8, Up: true, MAC: "02:00:00:00:00:16", Addrs: []string{"192.168.243.2/24"}},
		{Name: "eth7", Index: 9, Up: true, MAC: "02:00:00:00:00:17", Addrs: []string{"192.168.244.2/24"}},
	}

	if !autoBindDefaultInterfaceDevicesFromState(cfg, state, "eth3") {
		t.Fatalf("expected legacy index-order binding to be repaired")
	}

	got := map[string]string{}
	for _, iface := range cfg.Interfaces {
		got[iface.Name] = iface.Device
	}
	if got["wan"] != "eth3" {
		t.Fatalf("expected wan to repair to eth3, got %q", got["wan"])
	}
	if got["dmz"] != "eth4" {
		t.Fatalf("expected dmz to repair to eth4, got %q", got["dmz"])
	}
	if got["lan6"] != "eth2" {
		t.Fatalf("expected lan6 to repair to eth2, got %q", got["lan6"])
	}
}

func TestCreateFirewallRuleWithICSPredicate(t *testing.T) {
	m := &mockStore{cfg: &config.Config{Zones: []config.Zone{{Name: "ot"}}}}
	s := NewServer(m, nil)
	rec := httptest.NewRecorder()
	body := `{"id":"mb1","sourceZones":["ot"],"protocols":[{"name":"tcp","port":"502"}],"ics":{"protocol":"modbus","functionCode":[3,16],"addresses":["0-10"]},"action":"ALLOW"}`
	req := authedRequest(http.MethodPost, "/api/v1/firewall/rules", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	s.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d body=%s", rec.Code, rec.Body.String())
	}
	if len(m.cfg.Firewall.Rules) != 1 || m.cfg.Firewall.Rules[0].ICS.Protocol != "modbus" {
		t.Fatalf("ics predicate not persisted: %+v", m.cfg.Firewall.Rules)
	}
}

func TestUpdateFirewallRulePartialPatchPreservesExistingFields(t *testing.T) {
	m := &mockStore{
		cfg: &config.Config{
			Zones: []config.Zone{{Name: "lan1"}, {Name: "wan"}},
			Firewall: config.FirewallConfig{
				DefaultAction: config.ActionDeny,
				Rules: []config.Rule{{
					ID:          "audit-allow",
					Description: "old",
					SourceZones: []string{"lan1"},
					DestZones:   []string{"wan"},
					Action:      config.ActionAllow,
				}},
			},
		},
	}
	s := NewServer(m, nil)
	rec := httptest.NewRecorder()
	req := authedRequest(http.MethodPatch, "/api/v1/firewall/rules/audit-allow", bytes.NewBufferString(`{"description":"new"}`))
	req.Header.Set("Content-Type", "application/json")
	s.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d body=%s", rec.Code, rec.Body.String())
	}
	if got := m.cfg.Firewall.Rules[0].Description; got != "new" {
		t.Fatalf("expected description updated, got %q", got)
	}
	if got := m.cfg.Firewall.Rules[0].Action; got != config.ActionAllow {
		t.Fatalf("expected action preserved, got %q", got)
	}
}

func TestSetDHCPReturnsWarningWhenRuntimeApplyFails(t *testing.T) {
	m := &mockStore{
		cfg: &config.Config{
			Zones: []config.Zone{{Name: "lan1"}},
			Interfaces: []config.Interface{{
				Name: "lan1",
				Zone: "lan1",
			}},
		},
	}
	eng := &mockEngine{svcErr: errors.New("dhcp: nft apply failed: operation not permitted")}
	s := NewServerWithEngineAndServices(m, nil, eng, nil, nil)
	rec := httptest.NewRecorder()
	body := `{"enabled":true,"listenIfaces":["lan1"],"pools":[{"iface":"lan1","start":"10.0.0.10","end":"10.0.0.20"}],"router":"10.0.0.1","dnsServers":["10.0.0.1"]}`
	req := authedRequest(http.MethodPost, "/api/v1/services/dhcp", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	s.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d body=%s", rec.Code, rec.Body.String())
	}
	if got := rec.Header().Get("X-Containd-Warnings"); !strings.Contains(got, "engine services: dhcp: nft apply failed") {
		t.Fatalf("expected warning header, got %q", got)
	}
	if !m.cfg.Services.DHCP.Enabled {
		t.Fatal("expected DHCP config persisted despite runtime warning")
	}
}

func TestCandidateCommitRollback(t *testing.T) {
	m := &mockStore{}
	eng := &mockEngine{}
	s := NewServerWithEngine(m, nil, eng)

	rec := httptest.NewRecorder()
	req := authedRequest(http.MethodPost, "/api/v1/config/candidate", bytes.NewBufferString(`{"zones":[{"name":"it"}]}`))
	req.Header.Set("Content-Type", "application/json")
	s.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 saving candidate, got %d", rec.Code)
	}

	rec = httptest.NewRecorder()
	req = authedRequest(http.MethodPost, "/api/v1/config/commit", nil)
	s.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 committing, got %d", rec.Code)
	}
	if !eng.applied {
		t.Fatalf("expected engine apply on commit")
	}

	rec = httptest.NewRecorder()
	req = authedRequest(http.MethodPost, "/api/v1/config/rollback", nil)
	s.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 rollback, got %d", rec.Code)
	}
}

func TestConfigDiff(t *testing.T) {
	m := &mockStore{}
	m.cfg = &config.Config{Zones: []config.Zone{{Name: "running"}}}
	s := NewServer(m, nil)
	rec := httptest.NewRecorder()
	req := authedRequest(http.MethodGet, "/api/v1/config/diff", nil)
	s.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 diff, got %d", rec.Code)
	}
	if !bytes.Contains(rec.Body.Bytes(), []byte("running")) {
		t.Fatalf("diff missing running config")
	}
}

func TestExportImportConfig(t *testing.T) {
	resetTestRateLimiters()
	m := &mockStore{}
	s := NewServer(m, nil)

	importBody := `{"system":{"hostname":"containd"},"zones":[{"name":"it"}],"interfaces":[{"name":"eth0","zone":"it"}],"firewall":{"defaultAction":"ALLOW","rules":[]}}`
	rec := httptest.NewRecorder()
	req := authedRequest(http.MethodPost, "/api/v1/config/import", bytes.NewBufferString(importBody))
	req.Header.Set("Content-Type", "application/json")
	s.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("import expected 200, got %d body=%s", rec.Code, rec.Body.String())
	}

	rec = httptest.NewRecorder()
	req = authedRequest(http.MethodGet, "/api/v1/config/export", nil)
	s.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("export expected 200, got %d body=%s", rec.Code, rec.Body.String())
	}
	if !bytes.Contains(rec.Body.Bytes(), []byte(`"hostname":"containd"`)) {
		t.Fatalf("export missing hostname: %s", rec.Body.String())
	}
}

func TestImportConfigReplacesEmbeddedIDSRules(t *testing.T) {
	resetTestRateLimiters()
	dir := t.TempDir()
	store, err := config.NewSQLiteStore(filepath.Join(dir, "cfg.db"))
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer store.Close()

	oldRules := append([]config.IDSRule(nil), config.DefaultIDSConfig().Rules[:1]...)
	if err := store.SaveIDSRules(context.Background(), oldRules); err != nil {
		t.Fatalf("seed old ids rules: %v", err)
	}

	cfg := config.DefaultConfig()
	wantRules := append([]config.IDSRule(nil), config.DefaultIDSConfig().Rules[1:2]...)
	cfg.IDS.Rules = wantRules
	body, err := json.Marshal(cfg)
	if err != nil {
		t.Fatalf("marshal import config: %v", err)
	}

	s := NewServer(store, nil)
	rec := httptest.NewRecorder()
	req := authedRequest(http.MethodPost, "/api/v1/config/import", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	s.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("import expected 200, got %d body=%s", rec.Code, rec.Body.String())
	}

	gotRules, err := store.LoadIDSRules(context.Background())
	if err != nil {
		t.Fatalf("load ids rules after import: %v", err)
	}
	if len(gotRules) != len(wantRules) || gotRules[0].ID != wantRules[0].ID {
		t.Fatalf("ids rules not replaced on import: got=%v want=%v", gotRules, wantRules)
	}

	loaded, err := store.Load(context.Background())
	if err != nil {
		t.Fatalf("load config after import: %v", err)
	}
	if loaded.IDS.Rules != nil {
		t.Fatalf("expected imported config blob to strip embedded ids rules, got %d", len(loaded.IDS.Rules))
	}
}

func TestCommitConfirmedTTLParsing(t *testing.T) {
	m := &mockStore{}
	s := NewServer(m, nil)
	rec := httptest.NewRecorder()
	req := authedRequest(http.MethodPost, "/api/v1/config/commit_confirmed", bytes.NewBufferString(`{"ttl_seconds":5}`))
	req.Header.Set("Content-Type", "application/json")
	s.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d body=%s", rec.Code, rec.Body.String())
	}
	if m.lastTTL != 5*time.Second {
		t.Fatalf("expected ttl=5s, got %s", m.lastTTL)
	}
}

func TestConfirmCommitEndpoint(t *testing.T) {
	m := &mockStore{}
	s := NewServer(m, nil)
	rec := httptest.NewRecorder()
	req := authedRequest(http.MethodPost, "/api/v1/config/confirm", nil)
	s.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d body=%s", rec.Code, rec.Body.String())
	}
}

func TestSyslogHandlers(t *testing.T) {
	m := &mockStore{}
	s := NewServer(m, nil)

	body := `{"forwarders":[{"address":"1.2.3.4","port":514,"proto":"udp"}]}`
	rec := httptest.NewRecorder()
	req := authedRequest(http.MethodPost, "/api/v1/services/syslog", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	s.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}

	rec = httptest.NewRecorder()
	req = authedRequest(http.MethodGet, "/api/v1/services/syslog", nil)
	s.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}
	if !bytes.Contains(rec.Body.Bytes(), []byte(`"1.2.3.4"`)) {
		t.Fatalf("unexpected syslog payload: %s", rec.Body.String())
	}
}

func TestDataPlaneHandlers(t *testing.T) {
	m := &mockStore{}
	s := NewServer(m, nil)

	body := `{"captureInterfaces":["eth0"],"enforcement":true,"enforceTable":"containd","dpiMock":false}`
	rec := httptest.NewRecorder()
	req := authedRequest(http.MethodPost, "/api/v1/dataplane", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	s.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d body=%s", rec.Code, rec.Body.String())
	}

	rec = httptest.NewRecorder()
	req = authedRequest(http.MethodGet, "/api/v1/dataplane", nil)
	s.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK || !bytes.Contains(rec.Body.Bytes(), []byte(`"enforcement":true`)) {
		t.Fatalf("unexpected dataplane payload: %s", rec.Body.String())
	}
}

func TestSaveConfigValidationError(t *testing.T) {
	m := &mockStore{
		save: func(cfg *config.Config) error {
			return errors.New("invalid")
		},
	}
	s := NewServer(m, nil)
	rec := httptest.NewRecorder()
	req := authedRequest(http.MethodPost, "/api/v1/config", bytes.NewBufferString(`{"zones":[{"name":"it"}]}`))
	req.Header.Set("Content-Type", "application/json")
	s.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", rec.Code)
	}
}

func TestAssetCRUD(t *testing.T) {
	m := &mockStore{}
	s := NewServer(m, nil)

	rec := httptest.NewRecorder()
	req := authedRequest(http.MethodPost, "/api/v1/zones", bytes.NewBufferString(`{"name":"ot"}`))
	req.Header.Set("Content-Type", "application/json")
	s.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("zone create expected 200, got %d", rec.Code)
	}

	rec = httptest.NewRecorder()
	req = authedRequest(http.MethodPost, "/api/v1/assets", bytes.NewBufferString(`{"id":"a1","name":"plc-1","type":"PLC","zone":"ot","ips":["10.0.0.10"],"criticality":"HIGH"}`))
	req.Header.Set("Content-Type", "application/json")
	s.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("asset create expected 200, got %d body=%s", rec.Code, rec.Body.String())
	}

	rec = httptest.NewRecorder()
	req = authedRequest(http.MethodGet, "/api/v1/assets", nil)
	s.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK || !bytes.Contains(rec.Body.Bytes(), []byte(`"a1"`)) {
		t.Fatalf("asset list missing asset: %s", rec.Body.String())
	}

	rec = httptest.NewRecorder()
	req = authedRequest(http.MethodPatch, "/api/v1/assets/a1", bytes.NewBufferString(`{"description":"updated"}`))
	req.Header.Set("Content-Type", "application/json")
	s.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("asset update expected 200, got %d", rec.Code)
	}

	rec = httptest.NewRecorder()
	req = authedRequest(http.MethodDelete, "/api/v1/assets/a1", nil)
	s.ServeHTTP(rec, req)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("asset delete expected 204, got %d", rec.Code)
	}
}

func TestObjectCRUD(t *testing.T) {
	m := &mockStore{}
	s := NewServer(m, nil)

	rec := httptest.NewRecorder()
	req := authedRequest(http.MethodPost, "/api/v1/objects", bytes.NewBufferString(`{"id":"obj1","name":"plc-host","type":"HOST","addresses":["10.0.0.5"]}`))
	req.Header.Set("Content-Type", "application/json")
	s.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("object create expected 200, got %d body=%s", rec.Code, rec.Body.String())
	}

	rec = httptest.NewRecorder()
	req = authedRequest(http.MethodGet, "/api/v1/objects", nil)
	s.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK || !bytes.Contains(rec.Body.Bytes(), []byte(`"obj1"`)) {
		t.Fatalf("object list missing object: %s", rec.Body.String())
	}

	rec = httptest.NewRecorder()
	req = authedRequest(http.MethodPatch, "/api/v1/objects/obj1", bytes.NewBufferString(`{"description":"updated"}`))
	req.Header.Set("Content-Type", "application/json")
	s.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("object update expected 200, got %d", rec.Code)
	}

	rec = httptest.NewRecorder()
	req = authedRequest(http.MethodDelete, "/api/v1/objects/obj1", nil)
	s.ServeHTTP(rec, req)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("object delete expected 204, got %d", rec.Code)
	}
}
