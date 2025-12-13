package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"testing"
	"time"

	"github.com/containd/containd/pkg/cp/config"
)

type memStore struct {
	cfg *config.Config
}

func (m *memStore) Save(ctx context.Context, cfg *config.Config) error {
	m.cfg = cfg
	return nil
}

func (m *memStore) Load(ctx context.Context) (*config.Config, error) {
	if m.cfg == nil {
		return &config.Config{}, nil
	}
	return m.cfg, nil
}

func (m *memStore) SaveCandidate(ctx context.Context, cfg *config.Config) error {
	return m.Save(ctx, cfg)
}

func (m *memStore) LoadCandidate(ctx context.Context) (*config.Config, error) {
	return m.Load(ctx)
}

func (m *memStore) Commit(ctx context.Context) error   { return nil }
func (m *memStore) CommitConfirmed(ctx context.Context, ttl time.Duration) error {
	return nil
}
func (m *memStore) ConfirmCommit(ctx context.Context) error { return nil }
func (m *memStore) Rollback(ctx context.Context) error { return nil }

func (m *memStore) Close() error { return nil }

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
	if !bytes.Contains(buf.Bytes(), []byte("ok")) {
		t.Fatalf("expected ok response, got %s", buf.String())
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
	if len(client.reqs) != 1 {
		t.Fatalf("expected one request")
	}
	var body map[string]any
	_ = json.NewDecoder(client.reqs[0].Body).Decode(&body)
	if body["ttl_seconds"] != float64(5) {
		t.Fatalf("expected ttl_seconds=5, got %#v", body)
	}
}
