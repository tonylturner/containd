// SPDX-License-Identifier: Apache-2.0
package httpapi

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/tonylturner/containd/pkg/cp/audit"
	"github.com/tonylturner/containd/pkg/cp/users"
)

func TestFactoryResetWipesObservedAuditStore(t *testing.T) {
	ctx := context.Background()
	store, err := audit.NewSQLiteStore(filepath.Join(t.TempDir(), "audit.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	observed := audit.NewObservedStore(store)
	if err := observed.Add(ctx, audit.Record{Action: "before.reset", Result: "success"}); err != nil {
		t.Fatal(err)
	}

	rec := requestFactoryResetWithAuditStore(t, observed)
	var body struct {
		Warnings []string `json:"warnings"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if rec.Code != http.StatusOK || len(body.Warnings) != 0 || rec.Header().Get("X-Containd-Warnings") != "" {
		t.Fatalf("reset with observed audit store: %d %v %s", rec.Code, rec.Header(), rec.Body)
	}

	records, err := store.List(ctx, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(records) != 1 || records[0].Action != "system.factory_reset.completed" || records[0].Result != "success" {
		t.Fatalf("audit records after reset: %+v", records)
	}
}

func TestFactoryResetWarnsWhenAuditStoreCannotWipe(t *testing.T) {
	store, err := audit.NewSQLiteStore(filepath.Join(t.TempDir(), "audit.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	auditStore := auditStoreWithoutWipe{Store: store}
	if err := auditStore.Add(context.Background(), audit.Record{Action: "before.reset", Result: "success"}); err != nil {
		t.Fatal(err)
	}

	rec := requestFactoryResetWithAuditStore(t, auditStore)
	var body struct {
		Warnings []string `json:"warnings"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	const warning = "audit reset: store does not support wiping"
	if rec.Code != http.StatusOK || len(body.Warnings) != 1 || body.Warnings[0] != warning || rec.Header().Get("X-Containd-Warnings") == "" {
		t.Fatalf("reset without audit wipe capability: %d %v %s", rec.Code, rec.Header(), rec.Body)
	}
	records, err := store.List(context.Background(), 10)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, record := range records {
		found = found || record.Action == "before.reset"
	}
	if !found {
		t.Fatal("audit history disappeared despite the missing wipe capability")
	}
}

// Embedding the Store interface intentionally exposes no WipeAll capability.
type auditStoreWithoutWipe struct {
	audit.Store
}

func requestFactoryResetWithAuditStore(t *testing.T, auditStore audit.Store) *httptest.ResponseRecorder {
	t.Helper()
	t.Setenv("CONTAIND_LAB_MODE", "0")
	t.Setenv("CONTAIND_JWT_SECRET", "")
	t.Setenv("CONTAIND_DEFAULT_ADMIN_USERNAME", "")
	t.Setenv("CONTAIND_DEFAULT_ADMIN_PASSWORD", "")

	userStore, err := users.NewSQLiteStore(filepath.Join(t.TempDir(), "users.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = userStore.Close() })

	router := gin.New()
	router.Use(func(c *gin.Context) {
		c.Set("auditStore", auditStore)
		c.Next()
	})
	configStore := stageStore(t)
	router.POST("/reset", factoryResetHandler(configStore, userStore, &mockEngine{}, nil))

	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, withTestRevision(configStore, httptest.NewRequest(http.MethodPost, "/reset", bytes.NewBufferString(`{"confirm":"NUCLEAR"}`))))
	return rec
}
