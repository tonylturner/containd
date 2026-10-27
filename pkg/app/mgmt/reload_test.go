// SPDX-License-Identifier: Apache-2.0
package mgmtapp

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"sync"
	"testing"

	engineapi "github.com/tonylturner/containd/api/engine"
	"github.com/tonylturner/containd/pkg/cp/audit"
	"github.com/tonylturner/containd/pkg/cp/config"
	"github.com/tonylturner/containd/pkg/dp/rules"
	"go.uber.org/zap"
	"go.uber.org/zap/zaptest/observer"
)

type reloadServices struct {
	last config.ServicesConfig
}

func (s *reloadServices) Apply(_ context.Context, cfg config.ServicesConfig) error {
	s.last = cfg
	return nil
}

type invalidReloadStore struct{ *config.SQLiteStore }

func (s invalidReloadStore) Load(ctx context.Context) (*config.Config, error) {
	cfg, err := s.SQLiteStore.Load(ctx)
	if err == nil {
		cfg.Firewall.Rules = []config.Rule{{ID: "invalid", Action: "invalid"}}
	}
	return cfg, err
}

func TestReloadRunningConfigReappliesAndRecordsFailure(t *testing.T) {
	ctx := context.Background()
	store, err := config.NewSQLiteStore(filepath.Join(t.TempDir(), "config.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	audits, err := audit.NewSQLiteStore(filepath.Join(t.TempDir(), "audit.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer audits.Close()
	core, logs := observer.New(zap.InfoLevel)
	logger := zap.New(core).Sugar()
	var mu sync.Mutex
	var applied rules.Snapshot
	fail := false
	calls := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		calls++
		if fail && r.URL.Path == "/internal/config" {
			http.Error(w, "dataplane unavailable", http.StatusServiceUnavailable)
			return
		}
		if r.URL.Path == "/internal/apply_rules" {
			if err := json.NewDecoder(r.Body).Decode(&applied); err != nil {
				t.Error(err)
			}
		}
		_, _ = w.Write([]byte(`{}`))
	}))
	defer server.Close()
	engine := engineapi.NewHTTPClient(server.URL)
	services := &reloadServices{}
	cfg := config.DefaultConfig()
	cfg.Interfaces = nil
	cfg.Firewall.DefaultAction = config.ActionAllow
	if err := store.Save(ctx, cfg); err != nil {
		t.Fatal(err)
	}
	reloadRunningConfig(ctx, logger, store, audits, engine, services)
	mu.Lock()
	got := applied.Default
	mu.Unlock()
	if got != rules.ActionAllow {
		t.Fatalf("initial replay: %s", got)
	}
	cfg.Firewall.DefaultAction = config.ActionDeny
	cfg.Services.DNS.Enabled = true
	if err := store.Save(ctx, cfg); err != nil {
		t.Fatal(err)
	}
	reloadRunningConfig(ctx, logger, store, audits, engine, services)
	mu.Lock()
	got = applied.Default
	fail = true
	mu.Unlock()
	if got != rules.ActionDeny || !services.last.DNS.Enabled {
		t.Fatalf("changed running config not replayed: %s %+v", got, services.last)
	}
	reloadRunningConfig(ctx, logger, store, audits, engine, services)
	mu.Lock()
	got = applied.Default
	before := calls
	mu.Unlock()
	if got != rules.ActionDeny {
		t.Fatal("failed replay replaced the last installed rules")
	}
	fault, err := store.RuntimeApplyFault(ctx)
	if err != nil || fault == "" {
		t.Fatalf("failure not recorded: %q %v", fault, err)
	}
	reloadRunningConfig(ctx, logger, invalidReloadStore{store}, audits, engine, services)
	mu.Lock()
	after := calls
	mu.Unlock()
	if before != after {
		t.Fatal("invalid running config reached engine")
	}
	mu.Lock()
	fail = false
	mu.Unlock()
	reloadRunningConfig(ctx, logger, store, audits, engine, services)
	fault, err = store.RuntimeApplyFault(ctx)
	if err != nil || fault != "" {
		t.Fatalf("successful replay did not clear health fault: %q %v", fault, err)
	}
	records, err := audits.List(ctx, 10)
	if err != nil || len(records) != 5 {
		t.Fatalf("reload audits: %+v %v", records, err)
	}
	failures := 0
	for _, record := range records {
		if record.Action != "config.reload" || record.Source != "signal" {
			t.Fatalf("unexpected audit: %+v", record)
		}
		if record.Result == "failure" {
			failures++
		}
	}
	if failures != 2 || logs.FilterMessage("SIGHUP running configuration reload failed").Len() != 2 {
		t.Fatal("reload failures were not logged and audited")
	}
}
