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

	"github.com/tonylturner/containd/pkg/cp/config"
)

func TestDHCPAuthorityRoundTrip(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "config.db")
	store, err := config.NewSQLiteStore(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Save(ctx, config.DefaultConfig()); err != nil {
		t.Fatal(err)
	}
	server := NewServer(store, nil)
	call := func(method, path string, body []byte) *httptest.ResponseRecorder {
		t.Helper()
		req := authedRequest(method, "/api/v1"+path, bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		rec := httptest.NewRecorder()
		server.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("%s %s: %d %s", method, path, rec.Code, rec.Body.String())
		}
		return rec
	}
	for _, authority := range []bool{true, false} {
		body, err := json.Marshal(config.DHCPConfig{Authoritative: authority})
		if err != nil {
			t.Fatal(err)
		}
		for _, rec := range []*httptest.ResponseRecorder{call(http.MethodPost, "/services/dhcp", body), call(http.MethodGet, "/services/dhcp", nil)} {
			var got map[string]any
			if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
				t.Fatal(err)
			}
			if got["authoritative"] != authority {
				t.Fatalf("authority lost in service response: %s", rec.Body.String())
			}
		}
		if err := store.Commit(ctx); err != nil {
			t.Fatal(err)
		}
		exported := call(http.MethodGet, "/config/export", nil).Body.Bytes()
		var cfg config.Config
		if err := json.Unmarshal(exported, &cfg); err != nil {
			t.Fatal(err)
		}
		if cfg.Services.DHCP.Authoritative != authority {
			t.Fatal("authority lost in export")
		}
		call(http.MethodPost, "/config/import", exported)
		candidate, err := store.LoadCandidate(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if candidate.Services.DHCP.Authoritative != authority {
			t.Fatal("authority lost in import")
		}
		if err := store.Close(); err != nil {
			t.Fatal(err)
		}
		store, err = config.NewSQLiteStore(path)
		if err != nil {
			t.Fatal(err)
		}
		server = NewServer(store, nil)
		cfgp, err := store.Load(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if cfgp.Services.DHCP.Authoritative != authority {
			t.Fatal("authority lost on restart")
		}
	}
	defer store.Close()
	// Older configuration documents have no authority flag and remain passive.
	call(http.MethodPost, "/services/dhcp", []byte(`{"enabled":false}`))
	got, err := store.LoadCandidate(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if got.Services.DHCP.Authoritative {
		t.Fatal("omitted authority must default false")
	}
}
