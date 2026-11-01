// SPDX-License-Identifier: Apache-2.0
package httpapi

import (
	"context"
	"database/sql"
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"github.com/tonylturner/containd/pkg/cp/config"
)

func bankGCHandlerStore(t *testing.T, large bool) (*config.SQLiteStore, *sql.DB) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "config.db")
	store, err := config.NewSQLiteStore(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { store.Close() })
	ctx := context.Background()
	cfg := config.DefaultConfig()
	if err := store.Save(ctx, cfg); err != nil {
		t.Fatal(err)
	}
	template := cfg.IDS.Rules[0]
	size := 1
	if large {
		size = 30000
	}
	cfg.IDS.Rules = make([]config.IDSRule, size)
	for i := range cfg.IDS.Rules {
		cfg.IDS.Rules[i] = template
		cfg.IDS.Rules[i].ID = fmt.Sprintf("bank-%05d", i)
	}
	if err := testSaveCandidate(store, ctx, cfg); err != nil {
		t.Fatal(err)
	}
	if err := testCommitConfirmed(store, ctx, time.Hour); err != nil {
		t.Fatal(err)
	}
	inspector, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { inspector.Close() })
	return store, inspector
}

func assertHandlerBankBound(t *testing.T, db *sql.DB) {
	t.Helper()
	var count int
	if err := db.QueryRow(`SELECT count(*) FROM ids_banks`).Scan(&count); err != nil || count > 3 {
		t.Fatalf("unbounded bank generations: count=%d err=%v", count, err)
	}
}

func TestRepeatedIDSImportsReclaimBankGenerations(t *testing.T) {
	store, inspector := bankGCHandlerStore(t, true)
	server := NewServer(store, nil)
	for range 6 {
		rec := httptest.NewRecorder()
		serveWithConfigRevision(t, server, rec, idsApplyRequest(t, "import"))
		if rec.Code != http.StatusOK {
			t.Fatalf("import: %d %s", rec.Code, rec.Body)
		}
		assertHandlerBankBound(t, inspector)
	}
	cfgSnapshot1, err := store.ReadSnapshot(context.Background(), config.SnapshotCandidate, true)
	cfg := cfgSnapshot1.Candidate
	if err != nil || len(cfg.IDS.Rules) != 30001 {
		t.Fatalf("large-bank import/deduplication changed: %v", err)
	}
	if err := testRollback(store, context.Background()); err != nil {
		t.Fatal(err)
	}
	assertHandlerBankBound(t, inspector)
	if err := store.WipeAll(context.Background()); err != nil {
		t.Fatal(err)
	}
	var count int
	if err := inspector.QueryRow(`SELECT count(*) FROM ids_banks`).Scan(&count); err != nil || count != 0 {
		t.Fatalf("wipe retained banks: %d %v", count, err)
	}
}

func TestRepeatedIDSReplacementsReclaimBankGenerations(t *testing.T) {
	for _, action := range []string{"set", "restore", "full_config"} {
		t.Run(action, func(t *testing.T) {
			store, inspector := bankGCHandlerStore(t, false)
			server := NewServer(store, nil)
			for range 12 {
				rec := httptest.NewRecorder()
				if action == "full_config" {
					cfg := config.DefaultConfig()
					rec = requestStage(t, server, "POST", "/config/candidate", cfg)
				} else {
					serveWithConfigRevision(t, server, rec, idsApplyRequest(t, action))
				}
				if rec.Code != http.StatusOK {
					t.Fatalf("%s: %d %s", action, rec.Code, rec.Body)
				}
				assertHandlerBankBound(t, inspector)
			}
		})
	}
}
