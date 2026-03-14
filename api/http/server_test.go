// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

package httpapi

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/tonylturner/containd/pkg/cp/config"
	dpengine "github.com/tonylturner/containd/pkg/dp/engine"
	"github.com/tonylturner/containd/pkg/dp/pcap"
	"github.com/tonylturner/containd/pkg/dp/rules"
)

const testAdminToken = "test-admin-token"

func TestMain(m *testing.M) {
	gin.SetMode(gin.ReleaseMode)
	_ = os.Setenv("GIN_MODE", "release")
	_ = os.Setenv("CONTAIND_ADMIN_TOKEN", testAdminToken)
	_ = os.Setenv("CONTAIND_AUDITOR_TOKEN", "")
	_ = os.Setenv("CONTAIND_JWT_SECRET", "")
	_ = os.Setenv("CONTAIND_LAB_MODE", "0")
	code := m.Run()
	os.Exit(code)
}

func authedRequest(method, path string, body io.Reader) *http.Request {
	req, _ := http.NewRequest(method, path, body)
	req.Header.Set("Authorization", "Bearer "+testAdminToken)
	return req
}

type mockStore struct {
	cfg     *config.Config
	save    func(*config.Config) error
	load    func() (*config.Config, error)
	calls   int
	lastTTL time.Duration
}

func (m *mockStore) Save(ctx context.Context, cfg *config.Config) error {
	m.calls++
	if m.save != nil {
		return m.save(cfg)
	}
	if err := cfg.Validate(); err != nil {
		return err
	}
	m.cfg = cfg
	return nil
}

func (m *mockStore) Load(ctx context.Context) (*config.Config, error) {
	if m.load != nil {
		return m.load()
	}
	if m.cfg == nil {
		return nil, config.ErrNotFound
	}
	return m.cfg, nil
}

func (m *mockStore) SaveCandidate(ctx context.Context, cfg *config.Config) error {
	return m.Save(ctx, cfg)
}

func (m *mockStore) LoadCandidate(ctx context.Context) (*config.Config, error) {
	return m.Load(ctx)
}

func (m *mockStore) Commit(ctx context.Context) error { return nil }
func (m *mockStore) CommitConfirmed(ctx context.Context, ttl time.Duration) error {
	m.lastTTL = ttl
	return nil
}
func (m *mockStore) ConfirmCommit(ctx context.Context) error { return nil }
func (m *mockStore) Rollback(ctx context.Context) error      { return nil }
func (m *mockStore) SaveIDSRules(ctx context.Context, rules []config.IDSRule) error {
	return nil
}
func (m *mockStore) LoadIDSRules(ctx context.Context) ([]config.IDSRule, error) {
	return nil, nil
}
func (m *mockStore) Close() error { return nil }

type mockEngine struct {
	applied bool
	snap    rules.Snapshot
	err     error
	svcErr  error
	lastDP  config.DataPlaneConfig
	lastIf  []config.Interface
	lastRT  config.RoutingConfig
	lastRTR config.RoutingConfig
	lastSvc config.ServicesConfig
	state   []config.InterfaceState
	ruleset dpengine.RulesetStatus
}

func (m *mockEngine) Configure(ctx context.Context, cfg config.DataPlaneConfig) error {
	m.lastDP = cfg
	return nil
}

func (m *mockEngine) ConfigureInterfaces(ctx context.Context, ifaces []config.Interface) error {
	m.lastIf = append([]config.Interface(nil), ifaces...)
	return nil
}

func (m *mockEngine) ConfigureInterfacesReplace(ctx context.Context, ifaces []config.Interface) error {
	m.lastIf = append([]config.Interface(nil), ifaces...)
	return nil
}

func (m *mockEngine) ConfigureRouting(ctx context.Context, routing config.RoutingConfig) error {
	m.lastRT = routing
	return nil
}

func (m *mockEngine) ConfigureRoutingReplace(ctx context.Context, routing config.RoutingConfig) error {
	m.lastRTR = routing
	return nil
}

func (m *mockEngine) ConfigureServices(ctx context.Context, services config.ServicesConfig) error {
	m.lastSvc = services
	return m.svcErr
}

func (m *mockEngine) ListInterfaceState(ctx context.Context) ([]config.InterfaceState, error) {
	if m.state != nil {
		return m.state, nil
	}
	return []config.InterfaceState{{Name: "eth0", Index: 1, Up: true, Addrs: []string{"192.0.2.1/24"}}}, nil
}

func (m *mockEngine) ApplyRules(ctx context.Context, snap rules.Snapshot) error {
	m.applied = true
	m.snap = snap
	return m.err
}

func (m *mockEngine) RulesetStatus(ctx context.Context) (dpengine.RulesetStatus, error) {
	return m.ruleset, nil
}

func (m *mockEngine) PcapConfig(ctx context.Context) (config.PCAPConfig, error) {
	return config.PCAPConfig{}, nil
}

func (m *mockEngine) SetPcapConfig(ctx context.Context, cfg config.PCAPConfig) (config.PCAPConfig, error) {
	return cfg, nil
}

func (m *mockEngine) StartPcap(ctx context.Context, cfg config.PCAPConfig) (pcap.Status, error) {
	return pcap.Status{}, nil
}

func (m *mockEngine) StopPcap(ctx context.Context) (pcap.Status, error) {
	return pcap.Status{}, nil
}

func (m *mockEngine) PcapStatus(ctx context.Context) (pcap.Status, error) {
	return pcap.Status{}, nil
}

func (m *mockEngine) ListPcaps(ctx context.Context) ([]pcap.Item, error) {
	return []pcap.Item{}, nil
}

func (m *mockEngine) UploadPcap(ctx context.Context, filename string, r io.Reader) (pcap.Item, error) {
	return pcap.Item{Name: filename}, nil
}

func (m *mockEngine) DeletePcap(ctx context.Context, name string) error {
	return nil
}

func (m *mockEngine) TagPcap(ctx context.Context, req pcap.TagRequest) error {
	return nil
}

func (m *mockEngine) ReplayPcap(ctx context.Context, req pcap.ReplayRequest) error {
	return nil
}

func (m *mockEngine) DownloadPcap(ctx context.Context, name string) (*http.Response, error) {
	return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader("")), Header: http.Header{}}, nil
}

func (m *mockEngine) BlockHostTemp(ctx context.Context, ip net.IP, ttl time.Duration) error {
	return nil
}

func (m *mockEngine) BlockFlowTemp(ctx context.Context, srcIP, dstIP net.IP, proto string, dport string, ttl time.Duration) error {
	return nil
}

func TestGetConfigNotFound(t *testing.T) {
	s := NewServer(&mockStore{}, nil)
	rec := httptest.NewRecorder()
	req := authedRequest(http.MethodGet, "/api/v1/config", nil)
	s.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}
	var cfg config.Config
	if err := json.Unmarshal(rec.Body.Bytes(), &cfg); err != nil {
		t.Fatalf("invalid JSON response: %v", err)
	}
	if cfg.System.Hostname != "containd" {
		t.Fatalf("expected default hostname containd, got %q", cfg.System.Hostname)
	}
}

func TestSaveConfig(t *testing.T) {
	m := &mockStore{}
	s := NewServer(m, nil)
	body := bytes.NewBufferString(`{"system":{"hostname":"containd"},"zones":[{"name":"it"}]}`)
	rec := httptest.NewRecorder()
	req := authedRequest(http.MethodPost, "/api/v1/config", body)
	req.Header.Set("Content-Type", "application/json")
	s.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d body=%s", rec.Code, rec.Body.String())
	}
	if m.calls != 1 {
		t.Fatalf("expected save to be called once, got %d", m.calls)
	}
}

func TestValidateConfigBadJSON(t *testing.T) {
	s := NewServer(&mockStore{}, nil)
	rec := httptest.NewRecorder()
	req := authedRequest(http.MethodPost, "/api/v1/config/validate", bytes.NewBufferString(`{"zones": "oops"}`))
	req.Header.Set("Content-Type", "application/json")
	s.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", rec.Code)
	}
}

func TestCreateZone(t *testing.T) {
	m := &mockStore{}
	s := NewServer(m, nil)
	rec := httptest.NewRecorder()
	req := authedRequest(http.MethodPost, "/api/v1/zones", bytes.NewBufferString(`{"name":"it"}`))
	req.Header.Set("Content-Type", "application/json")
	s.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d body=%s", rec.Code, rec.Body.String())
	}
	if m.cfg == nil || len(m.cfg.Zones) == 0 {
		t.Fatalf("expected zones to be persisted")
	}
	found := false
	for _, z := range m.cfg.Zones {
		if z.Name == "it" {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("zone not persisted: %+v", m.cfg)
	}
}

func TestCreateInterfaceValidation(t *testing.T) {
	m := &mockStore{}
	s := NewServer(m, nil)
	rec := httptest.NewRecorder()
	body := bytes.NewBufferString(`{"name":"eth0","zone":"missing"}`)
	req := authedRequest(http.MethodPost, "/api/v1/interfaces", body)
	req.Header.Set("Content-Type", "application/json")
	s.ServeHTTP(rec, req)
	if rec.Code == http.StatusOK {
		t.Fatalf("expected validation error, got 200")
	}
}

func TestCreateRuleDuplicate(t *testing.T) {
	m := &mockStore{
		cfg: &config.Config{
			Firewall: config.FirewallConfig{
				DefaultAction: config.ActionDeny,
				Rules: []config.Rule{
					{ID: "1", Action: config.ActionAllow},
				},
			},
		},
	}
	s := NewServer(m, nil)
	rec := httptest.NewRecorder()
	req := authedRequest(http.MethodPost, "/api/v1/firewall/rules", bytes.NewBufferString(`{"id":"1","action":"ALLOW"}`))
	req.Header.Set("Content-Type", "application/json")
	s.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for duplicate, got %d", rec.Code)
	}
}

func TestGetAndSetFirewallNAT(t *testing.T) {
	m := &mockStore{}
	s := NewServer(m, nil)

	// GET returns default (disabled) NAT config.
	{
		rec := httptest.NewRecorder()
		req := authedRequest(http.MethodGet, "/api/v1/firewall/nat", nil)
		s.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("expected 200, got %d body=%s", rec.Code, rec.Body.String())
		}
		var nat config.NATConfig
		if err := json.Unmarshal(rec.Body.Bytes(), &nat); err != nil {
			t.Fatalf("invalid JSON response: %v", err)
		}
		if nat.Enabled {
			t.Fatalf("expected nat disabled by default, got enabled")
		}
	}

	// POST updates NAT config (valid zones).
	{
		rec := httptest.NewRecorder()
		req := authedRequest(http.MethodPost, "/api/v1/firewall/nat", bytes.NewBufferString(`{"enabled":true,"egressZone":"wan","sourceZones":["lan","dmz"]}`))
		req.Header.Set("Content-Type", "application/json")
		s.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("expected 200, got %d body=%s", rec.Code, rec.Body.String())
		}
	}

	// POST with unknown egress zone fails validation.
	{
		rec := httptest.NewRecorder()
		req := authedRequest(http.MethodPost, "/api/v1/firewall/nat", bytes.NewBufferString(`{"enabled":true,"egressZone":"nope","sourceZones":["lan"]}`))
		req.Header.Set("Content-Type", "application/json")
		s.ServeHTTP(rec, req)
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("expected 400, got %d body=%s", rec.Code, rec.Body.String())
		}
	}
}

func TestUpdateZone(t *testing.T) {
	m := &mockStore{
		cfg: &config.Config{
			Zones: []config.Zone{{Name: "it", Description: "old"}},
		},
	}
	s := NewServer(m, nil)
	rec := httptest.NewRecorder()
	req := authedRequest(http.MethodPatch, "/api/v1/zones/it", bytes.NewBufferString(`{"description":"new"}`))
	req.Header.Set("Content-Type", "application/json")
	s.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}
	if m.cfg.Zones[0].Description != "new" {
		t.Fatalf("zone not updated")
	}
}

func TestUpdateInterfaceNotFound(t *testing.T) {
	m := &mockStore{cfg: &config.Config{}}
	s := NewServer(m, nil)
	rec := httptest.NewRecorder()
	req := authedRequest(http.MethodPatch, "/api/v1/interfaces/eth0", bytes.NewBufferString(`{"zone":"it"}`))
	req.Header.Set("Content-Type", "application/json")
	s.ServeHTTP(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("expected 404, got %d", rec.Code)
	}
}
