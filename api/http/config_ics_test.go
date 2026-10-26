// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 containd Authors

package httpapi

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/tonylturner/containd/pkg/cp/config"
)

func TestGetConfigPreservesRangerDangerFirewallHash(t *testing.T) {
	submitted, err := os.ReadFile(filepath.Join("..", "..", "docs", "iec104", "testdata", "exact-policy.json"))
	if err != nil {
		t.Fatal(err)
	}
	var cfg config.Config
	if err := json.Unmarshal(submitted, &cfg); err != nil {
		t.Fatal(err)
	}
	store, err := config.NewSQLiteStore(filepath.Join(t.TempDir(), "config.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	if err := store.Save(context.Background(), &cfg); err != nil {
		t.Fatal(err)
	}

	rec := httptest.NewRecorder()
	NewServer(store, nil).ServeHTTP(rec, authedRequest(http.MethodGet, "/api/v1/config", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /config = %d: %s", rec.Code, rec.Body.String())
	}
	gotHash := canonicalFirewallHash(t, rec.Body.Bytes())
	wantHash := canonicalFirewallHash(t, submitted)
	if gotHash != wantHash {
		t.Fatalf("GET /config firewall hash = %s, submitted firewall hash = %s", gotHash, wantHash)
	}
}

func canonicalFirewallHash(t *testing.T, body []byte) string {
	t.Helper()
	var configObject map[string]json.RawMessage
	if err := json.Unmarshal(body, &configObject); err != nil {
		t.Fatal(err)
	}
	firewall, ok := configObject["firewall"]
	if !ok {
		t.Fatal("config has no firewall object")
	}
	var decoded any
	if err := json.Unmarshal(firewall, &decoded); err != nil {
		t.Fatal(err)
	}
	canonical, err := json.Marshal(decoded)
	if err != nil {
		t.Fatal(err)
	}
	hash := sha256.Sum256(canonical)
	return hex.EncodeToString(hash[:])
}
