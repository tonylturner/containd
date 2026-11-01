// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"testing"
	"time"

	"github.com/tonylturner/containd/pkg/cp/config"
)

type memStore struct {
	cfg      *config.Config
	revision uint64
}

func (m *memStore) Save(ctx context.Context, cfg *config.Config) error {
	m.cfg = cfg
	m.revision++
	return nil
}

func (m *memStore) Load(ctx context.Context) (*config.Config, error) {
	if m.cfg == nil {
		return &config.Config{}, nil
	}
	return m.cfg, nil
}

func (m *memStore) MutateCandidate(ctx context.Context, expected config.Revision, edit func(*config.Config) error) (config.Revision, error) {
	if expected != m.currentRevision() {
		return "", &config.ErrRevisionMismatch{CurrentRevision: m.currentRevision()}
	}
	cfg, err := m.LoadCandidate(ctx)
	if err != nil && err != config.ErrNotFound {
		return "", err
	}
	if cfg == nil {
		cfg = config.DefaultConfig()
	}
	blob, err := json.Marshal(cfg)
	if err != nil {
		return "", err
	}
	var next config.Config
	if err := json.Unmarshal(blob, &next); err != nil {
		return "", err
	}
	bank := next.IDS.Rules
	next.IDS.Rules = nil
	if err := edit(&next); err != nil {
		return "", err
	}
	if next.IDS.Rules != nil {
		return "", errors.New("bank-free candidate edit supplied IDS rules")
	}
	next.IDS.Rules = bank
	return m.SaveCandidate(ctx, expected, &next)
}

func (m *memStore) SaveCandidate(ctx context.Context, expected config.Revision, cfg *config.Config) (config.Revision, error) {
	if expected != m.currentRevision() {
		return "", &config.ErrRevisionMismatch{CurrentRevision: m.currentRevision()}
	}
	if err := m.Save(ctx, cfg); err != nil {
		return "", err
	}
	return m.currentRevision(), nil
}

func (m *memStore) LoadCandidate(ctx context.Context) (*config.Config, error) {
	return m.Load(ctx)
}

func (m *memStore) currentRevision() config.Revision {
	return config.Revision(fmt.Sprintf("0123456789abcdef.%d", m.revision+1))
}
func (m *memStore) ReadSnapshot(ctx context.Context, _ config.SnapshotKind, withBank bool) (config.ConfigSnapshot, error) {
	cfg, err := m.Load(ctx)
	return config.ConfigSnapshot{Running: cfg, Candidate: cfg, Revision: m.currentRevision()}, err
}
func (m *memStore) Commit(ctx context.Context, expected config.Revision) (config.Revision, error) {
	if expected != m.currentRevision() {
		return "", &config.ErrRevisionMismatch{CurrentRevision: m.currentRevision()}
	}
	m.revision++
	return m.currentRevision(), nil
}
func (m *memStore) CommitConfirmed(ctx context.Context, expected config.Revision, ttl time.Duration) (config.Revision, error) {
	return m.Commit(ctx, expected)
}
func (m *memStore) ConfirmCommit(ctx context.Context, expected config.Revision) (config.Revision, error) {
	return m.Commit(ctx, expected)
}
func (m *memStore) Rollback(ctx context.Context, expected config.Revision) (config.Revision, error) {
	return m.Commit(ctx, expected)
}
func (m *memStore) SaveIDSRules(ctx context.Context, rules []config.IDSRule) error {
	return nil
}
func (m *memStore) LoadIDSRules(ctx context.Context) ([]config.IDSRule, error) {
	return nil, nil
}
func (m *memStore) Close() error { return nil }

func TestMemStoreBankFreeCandidateEdits(t *testing.T) {
	for _, tc := range []struct {
		name    string
		rules   []config.IDSRule
		editErr error
		wantErr string
	}{
		{name: "ordinary edit retains bank"},
		{name: "reject explicit empty bank", rules: []config.IDSRule{}, wantErr: "bank-free candidate edit supplied IDS rules"},
		{name: "reject replacement bank", rules: []config.IDSRule{{ID: "replacement"}}, wantErr: "bank-free candidate edit supplied IDS rules"},
		{name: "failed callback leaves candidate unchanged", editErr: errors.New("edit failed"), wantErr: "edit failed"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := config.DefaultConfig()
			cfg.System.Hostname = "before"
			cfg.IDS.Rules = []config.IDSRule{{ID: "retained", Labels: map[string]string{"source": "saved"}}}
			store := &memStore{cfg: cfg}
			_, err := store.MutateCandidate(context.Background(), store.currentRevision(), func(next *config.Config) error {
				if next.IDS.Rules != nil {
					t.Fatal("bank-free callback received IDS rules")
				}
				next.System.Hostname = "after"
				next.IDS.Rules = tc.rules
				return tc.editErr
			})
			if tc.wantErr == "" {
				if err != nil {
					t.Fatal(err)
				}
				if store.cfg.System.Hostname != "after" {
					t.Fatal("ordinary edit was not saved")
				}
			} else {
				if err == nil || err.Error() != tc.wantErr {
					t.Fatalf("error = %v, want %q", err, tc.wantErr)
				}
				if store.cfg.System.Hostname != "before" {
					t.Fatal("failed edit changed candidate")
				}
			}
			bank := store.cfg.IDS.Rules
			if len(bank) != 1 || bank[0].ID != "retained" || bank[0].Labels["source"] != "saved" {
				t.Fatalf("bank changed: %+v", bank)
			}
		})
	}
}

func TestShowVersion(t *testing.T) {
	reg := NewRegistry(&memStore{}, nil)
	var buf bytes.Buffer
	if err := reg.Execute(context.Background(), "show version", &buf, nil); err != nil {
		t.Fatalf("execute: %v", err)
	}
	if buf.String() == "" {
		t.Fatalf("expected output")
	}
}

func TestShowZones(t *testing.T) {
	store := &memStore{cfg: &config.Config{Zones: []config.Zone{{Name: "it"}}}}
	reg := NewRegistry(store, nil)
	var buf bytes.Buffer
	if err := reg.Execute(context.Background(), "show zones", &buf, nil); err != nil {
		t.Fatalf("execute: %v", err)
	}
	if !bytes.Contains(buf.Bytes(), []byte("NAME")) || !bytes.Contains(buf.Bytes(), []byte("it")) {
		t.Fatalf("unexpected output: %q", buf.String())
	}
}

func TestUnknownCommand(t *testing.T) {
	reg := NewRegistry(&memStore{}, nil)
	err := reg.Execute(context.Background(), "does not exist", nil, nil)
	if err == nil {
		t.Fatalf("expected error for unknown command")
	}
}

func TestParseAndExecuteMatchesLongestPrefix(t *testing.T) {
	reg := NewRegistry(&memStore{}, nil)
	var buf bytes.Buffer
	if err := reg.ParseAndExecute(context.Background(), "show version", &buf); err != nil {
		t.Fatalf("parse execute: %v", err)
	}
	if buf.String() == "" {
		t.Fatalf("expected output")
	}
}

func TestHelpCommands(t *testing.T) {
	reg := NewRegistry(&memStore{}, nil)
	var buf bytes.Buffer
	if err := reg.ParseAndExecute(context.Background(), "help", &buf); err != nil {
		t.Fatalf("help: %v", err)
	}
	if !bytes.Contains(buf.Bytes(), []byte("Available commands")) {
		t.Fatalf("unexpected help output: %s", buf.String())
	}
	buf.Reset()
	if err := reg.ParseAndExecute(context.Background(), "show help", &buf); err != nil {
		t.Fatalf("show help: %v", err)
	}
	if !bytes.Contains(buf.Bytes(), []byte("show commands")) {
		t.Fatalf("unexpected show help output: %s", buf.String())
	}
}

func TestShowInterfacesOS(t *testing.T) {
	reg := NewRegistry(&memStore{}, nil)
	var buf bytes.Buffer
	if err := reg.ParseAndExecute(context.Background(), "show interfaces os", &buf); err != nil {
		t.Fatalf("execute: %v", err)
	}
	if !bytes.Contains(buf.Bytes(), []byte("IFACE")) || !bytes.Contains(buf.Bytes(), []byte("ADDRS")) {
		t.Fatalf("unexpected output: %s", buf.String())
	}
}

func TestSetSystemHostnameUsage(t *testing.T) {
	// API-backed command exists only when API is provided.
	client := &mockHTTPClient{
		resp: &http.Response{
			StatusCode: http.StatusOK,
			Body:       io.NopCloser(bytes.NewBufferString(`{}`)),
		},
	}
	api := &API{BaseURL: "http://localhost:8080", Client: client}
	reg := NewRegistry(nil, api)
	var buf bytes.Buffer
	ctx := WithRole(context.Background(), string(RoleAdmin))
	err := reg.ParseAndExecute(ctx, "set system hostname containd", &buf)
	if err != nil {
		t.Fatalf("expected set system hostname to execute, got %v", err)
	}
}

func TestShowServicesStatusTable(t *testing.T) {
	body := bytes.NewBufferString(`{
	  "syslog": {"configured_forwarders": 2},
	  "proxy": {
	    "forward_enabled": true,
	    "reverse_enabled": false,
	    "envoy_running": true,
	    "nginx_running": false,
	    "envoy_path": "/usr/bin/envoy",
	    "nginx_path": "/usr/sbin/nginx"
	  }
	}`)
	client := &mockHTTPClient{
		resp: &http.Response{
			StatusCode: http.StatusOK,
			Body:       io.NopCloser(body),
		},
	}
	api := &API{BaseURL: "http://localhost:8080", Client: client}
	reg := NewRegistry(nil, api)
	var buf bytes.Buffer
	if err := reg.ParseAndExecute(context.Background(), "show services status", &buf); err != nil {
		t.Fatalf("execute: %v", err)
	}
	if !bytes.Contains(buf.Bytes(), []byte("SERVICE")) || !bytes.Contains(buf.Bytes(), []byte("envoy-forward")) {
		t.Fatalf("unexpected output: %s", buf.String())
	}
}

type mockHTTPClient struct {
	resp *http.Response
	err  error
	reqs []*http.Request
}

func (m *mockHTTPClient) Do(req *http.Request) (*http.Response, error) {
	m.reqs = append(m.reqs, req)
	if m.err != nil {
		return nil, m.err
	}
	if req.Method == "GET" && req.URL.Path == "/api/v1/config/candidate" {
		return jsonHTTPResponse(http.StatusOK, config.DefaultConfig(), nil), nil
	}
	if m.resp.Header == nil {
		m.resp.Header = make(http.Header)
	}
	m.resp.Header.Set("X-Containd-Revision", "0123456789abcdef.2")
	return m.resp, nil
}

func TestShowHealthViaAPI(t *testing.T) {
	body := bytes.NewBufferString(`{"status":"ok"}`)
	client := &mockHTTPClient{
		resp: &http.Response{
			StatusCode: http.StatusOK,
			Body:       io.NopCloser(body),
		},
	}
	api := &API{BaseURL: "http://localhost:8080", Client: client}
	reg := NewRegistry(nil, api)
	var buf bytes.Buffer
	if err := reg.Execute(context.Background(), "show health", &buf, nil); err != nil {
		t.Fatalf("execute: %v", err)
	}
	if !bytes.Contains(buf.Bytes(), []byte("status")) {
		t.Fatalf("expected health output, got %s", buf.String())
	}
}

func TestShowZonesViaAPI(t *testing.T) {
	body := bytes.NewBufferString(`[{"name":"it"},{"name":"dmz","description":"dmz"}]`)
	client := &mockHTTPClient{
		resp: &http.Response{
			StatusCode: http.StatusOK,
			Body:       io.NopCloser(body),
		},
	}
	api := &API{BaseURL: "http://localhost:8080", Client: client}
	reg := NewRegistry(nil, api)
	var buf bytes.Buffer
	if err := reg.Execute(context.Background(), "show zones", &buf, nil); err != nil {
		t.Fatalf("execute: %v", err)
	}
	if !bytes.Contains(buf.Bytes(), []byte("it")) {
		t.Fatalf("expected zones output, got %s", buf.String())
	}
}

func TestShowAssetsViaAPI(t *testing.T) {
	body := bytes.NewBufferString(`[{"id":"a1","name":"PLC-1","type":"PLC","zone":"lan","ips":["10.0.0.10"],"criticality":"HIGH","tags":["ot"]}]`)
	client := &mockHTTPClient{
		resp: &http.Response{
			StatusCode: http.StatusOK,
			Body:       io.NopCloser(body),
		},
	}
	api := &API{BaseURL: "http://localhost:8080", Client: client}
	reg := NewRegistry(nil, api)
	var buf bytes.Buffer
	if err := reg.Execute(context.Background(), "show assets", &buf, nil); err != nil {
		t.Fatalf("execute: %v", err)
	}
	if !bytes.Contains(buf.Bytes(), []byte("PLC-1")) || !bytes.Contains(buf.Bytes(), []byte("HIGH")) {
		t.Fatalf("unexpected output: %s", buf.String())
	}
}

func TestShowFirewallRulesViaAPI(t *testing.T) {
	body := bytes.NewBufferString(`[{"id":"r1","sourceZones":["lan"],"destZones":["wan"],"protocols":[{"name":"tcp","port":"443"}],"action":"ALLOW"}]`)
	client := &mockHTTPClient{
		resp: &http.Response{
			StatusCode: http.StatusOK,
			Body:       io.NopCloser(body),
		},
	}
	api := &API{BaseURL: "http://localhost:8080", Client: client}
	reg := NewRegistry(nil, api)
	var buf bytes.Buffer
	if err := reg.Execute(context.Background(), "show firewall rules", &buf, nil); err != nil {
		t.Fatalf("execute: %v", err)
	}
	if !bytes.Contains(buf.Bytes(), []byte("tcp/443")) || !bytes.Contains(buf.Bytes(), []byte("ALLOW")) {
		t.Fatalf("unexpected output: %s", buf.String())
	}
}

func TestDiagTCPTracerouteUsage(t *testing.T) {
	reg := NewRegistry(&memStore{}, nil)
	var buf bytes.Buffer
	err := reg.ParseAndExecute(context.Background(), "diag tcptraceroute", &buf)
	if err == nil {
		t.Fatalf("expected usage error")
	}
}

func TestSetZoneViaAPI(t *testing.T) {
	client := &mockHTTPClient{
		resp: &http.Response{
			StatusCode: http.StatusOK,
			Header:     http.Header{"X-Containd-Config": []string{"staged"}},
			Body:       io.NopCloser(bytes.NewBuffer(nil)),
		},
	}
	api := &API{BaseURL: "http://localhost:8080", Client: client}
	reg := NewRegistry(nil, api)
	var buf bytes.Buffer
	ctx := WithRole(context.Background(), string(RoleAdmin))
	if err := reg.Execute(ctx, "set zone", &buf, []string{"it", "desc"}); err != nil {
		t.Fatalf("execute: %v", err)
	}
	if !bytes.Contains(buf.Bytes(), []byte(stagedMessage)) {
		t.Fatalf("expected staged response, got %s", buf.String())
	}
}

func TestDeleteFirewallRuleViaAPI(t *testing.T) {
	client := &mockHTTPClient{
		resp: &http.Response{
			StatusCode: http.StatusNoContent,
			Body:       io.NopCloser(bytes.NewBuffer(nil)),
		},
	}
	api := &API{BaseURL: "http://localhost:8080", Client: client}
	reg := NewRegistry(nil, api)
	var buf bytes.Buffer
	ctx := WithRole(context.Background(), string(RoleAdmin))
	if err := reg.Execute(ctx, "delete firewall rule", &buf, []string{"10"}); err != nil {
		t.Fatalf("execute: %v", err)
	}
}

func TestCommitConfirmedViaAPI(t *testing.T) {
	client := &mockHTTPClient{
		resp: &http.Response{
			StatusCode: http.StatusOK,
			Body:       io.NopCloser(bytes.NewBuffer(nil)),
		},
	}
	api := &API{BaseURL: "http://localhost:8080", Client: client}
	reg := NewRegistry(nil, api)
	var buf bytes.Buffer
	ctx := WithRole(context.Background(), string(RoleAdmin))
	if err := reg.Execute(ctx, "commit confirmed", &buf, []string{"5"}); err != nil {
		t.Fatalf("execute: %v", err)
	}
	if len(client.reqs) != 2 || client.reqs[0].URL.Path != "/api/v1/config/candidate" {
		t.Fatalf("expected candidate read then commit, got %v", client.reqs)
	}
	var body map[string]any
	_ = json.NewDecoder(client.reqs[1].Body).Decode(&body)
	if body["ttl_seconds"] != float64(5) {
		t.Fatalf("expected ttl_seconds=5, got %#v", body)
	}
}
