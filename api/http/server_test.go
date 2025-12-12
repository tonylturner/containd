package httpapi

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/containd/containd/pkg/cp/config"
)

type mockStore struct {
	cfg   *config.Config
	save  func(*config.Config) error
	load  func() (*config.Config, error)
	calls int
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

func (m *mockStore) Commit(ctx context.Context) error   { return nil }
func (m *mockStore) CommitConfirmed(ctx context.Context, ttl time.Duration) error {
	m.lastTTL = ttl
	return nil
}
func (m *mockStore) ConfirmCommit(ctx context.Context) error { return nil }
func (m *mockStore) Rollback(ctx context.Context) error { return nil }
func (m *mockStore) Close() error { return nil }

func TestGetConfigNotFound(t *testing.T) {
	s := NewServer(&mockStore{}, nil)
	rec := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/api/v1/config", nil)
	s.ServeHTTP(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("expected 404, got %d", rec.Code)
	}
}

func TestSaveConfig(t *testing.T) {
    m := &mockStore{}
    s := NewServer(m, nil)
	body := bytes.NewBufferString(`{"system":{"hostname":"containd"},"zones":[{"name":"it"}]}`)
	rec := httptest.NewRecorder()
	req, _ := http.NewRequest("POST", "/api/v1/config", body)
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
	req, _ := http.NewRequest("POST", "/api/v1/config/validate", bytes.NewBufferString(`{"zones": "oops"}`))
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
	req, _ := http.NewRequest("POST", "/api/v1/zones", bytes.NewBufferString(`{"name":"dmz"}`))
	req.Header.Set("Content-Type", "application/json")
	s.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d body=%s", rec.Code, rec.Body.String())
	}
	if m.cfg == nil || len(m.cfg.Zones) != 1 || m.cfg.Zones[0].Name != "dmz" {
		t.Fatalf("zone not persisted: %+v", m.cfg)
	}
}

func TestCreateInterfaceValidation(t *testing.T) {
	m := &mockStore{}
	s := NewServer(m, nil)
	rec := httptest.NewRecorder()
	body := bytes.NewBufferString(`{"name":"eth0","zone":"missing"}`)
	req, _ := http.NewRequest("POST", "/api/v1/interfaces", body)
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
				DefaultAction: config.ActionAllow,
				Rules: []config.Rule{
					{ID: "1", Action: config.ActionAllow},
				},
			},
		},
	}
    s := NewServer(m, nil)
	rec := httptest.NewRecorder()
	req, _ := http.NewRequest("POST", "/api/v1/firewall/rules", bytes.NewBufferString(`{"id":"1","action":"ALLOW"}`))
	req.Header.Set("Content-Type", "application/json")
	s.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for duplicate, got %d", rec.Code)
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
	req, _ := http.NewRequest("PATCH", "/api/v1/zones/it", bytes.NewBufferString(`{"description":"new"}`))
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
	req, _ := http.NewRequest("PATCH", "/api/v1/interfaces/eth0", bytes.NewBufferString(`{"zone":"it"}`))
	req.Header.Set("Content-Type", "application/json")
	s.ServeHTTP(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("expected 404, got %d", rec.Code)
	}
}

func TestCandidateCommitRollback(t *testing.T) {
	m := &mockStore{}
	s := NewServer(m, nil)

	// Save candidate
	rec := httptest.NewRecorder()
	req, _ := http.NewRequest("POST", "/api/v1/config/candidate", bytes.NewBufferString(`{"zones":[{"name":"it"}]}`))
	req.Header.Set("Content-Type", "application/json")
	s.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 saving candidate, got %d", rec.Code)
	}

	// Commit
	rec = httptest.NewRecorder()
	req, _ = http.NewRequest("POST", "/api/v1/config/commit", nil)
	s.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 committing, got %d", rec.Code)
	}

	// Rollback
	rec = httptest.NewRecorder()
	req, _ = http.NewRequest("POST", "/api/v1/config/rollback", nil)
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
	req, _ := http.NewRequest("GET", "/api/v1/config/diff", nil)
	s.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 diff, got %d", rec.Code)
	}
	if !bytes.Contains(rec.Body.Bytes(), []byte("running")) {
		t.Fatalf("diff missing running config")
	}
}

func TestExportImportConfig(t *testing.T) {
	m := &mockStore{}
	s := NewServer(m, nil)

	// Import config
	importBody := `{"system":{"hostname":"containd"},"zones":[{"name":"it"}],"interfaces":[{"name":"eth0","zone":"it"}],"firewall":{"defaultAction":"ALLOW","rules":[]}}`
	rec := httptest.NewRecorder()
	req, _ := http.NewRequest("POST", "/api/v1/config/import", bytes.NewBufferString(importBody))
	req.Header.Set("Content-Type", "application/json")
	s.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("import expected 200, got %d body=%s", rec.Code, rec.Body.String())
	}

	// Export should return same hostname
	rec = httptest.NewRecorder()
	req, _ = http.NewRequest("GET", "/api/v1/config/export", nil)
	s.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("export expected 200, got %d body=%s", rec.Code, rec.Body.String())
	}
	if !bytes.Contains(rec.Body.Bytes(), []byte(`"hostname":"containd"`)) {
		t.Fatalf("export missing hostname: %s", rec.Body.String())
	}
}

func TestCommitConfirmedTTLParsing(t *testing.T) {
	m := &mockStore{}
	s := NewServer(m, nil)
	rec := httptest.NewRecorder()
	req, _ := http.NewRequest("POST", "/api/v1/config/commit_confirmed", bytes.NewBufferString(`{"ttl_seconds":5}`))
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
	req, _ := http.NewRequest("POST", "/api/v1/config/confirm", nil)
	s.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d body=%s", rec.Code, rec.Body.String())
	}
}

func TestSyslogHandlers(t *testing.T) {
	m := &mockStore{}
	s := NewServer(m, nil)

	// Set syslog
	body := `{"forwarders":[{"address":"1.2.3.4","port":514,"proto":"udp"}]}`
	rec := httptest.NewRecorder()
	req, _ := http.NewRequest("POST", "/api/v1/services/syslog", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	s.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}

	// Get syslog
	rec = httptest.NewRecorder()
	req, _ = http.NewRequest("GET", "/api/v1/services/syslog", nil)
	s.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}
	if !bytes.Contains(rec.Body.Bytes(), []byte(`"1.2.3.4"`)) {
		t.Fatalf("unexpected syslog payload: %s", rec.Body.String())
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
	req, _ := http.NewRequest("POST", "/api/v1/config", bytes.NewBufferString(`{"zones":[{"name":"it"}]}`))
	req.Header.Set("Content-Type", "application/json")
	s.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", rec.Code)
	}
}
