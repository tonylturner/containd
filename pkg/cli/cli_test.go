package cli

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"testing"

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
	if got := buf.String(); got == "" || got != "it\n" {
		t.Fatalf("unexpected output: %q", got)
	}
}

func TestUnknownCommand(t *testing.T) {
	reg := NewRegistry(&memStore{}, nil)
	err := reg.Execute(context.Background(), "does not exist", nil, nil)
	if err == nil {
		t.Fatalf("expected error for unknown command")
	}
}

type mockHTTPClient struct {
	resp *http.Response
	err  error
}

func (m *mockHTTPClient) Do(req *http.Request) (*http.Response, error) {
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
	if err := reg.Execute(context.Background(), "set zone", &buf, []string{"it", "desc"}); err != nil {
		t.Fatalf("execute: %v", err)
	}
	if !bytes.Contains(buf.Bytes(), []byte("ok")) {
		t.Fatalf("expected ok response, got %s", buf.String())
	}
}
