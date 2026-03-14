// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

package mgmtapp

import (
	"crypto/tls"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/tonylturner/containd/pkg/cp/config"
)

func TestResolveTLSFiles(t *testing.T) {
	cfg := &config.Config{}
	cert, key := resolveTLSFiles(cfg)
	if cert != "/data/tls/server.crt" || key != "/data/tls/server.key" {
		t.Fatalf("default tls files = %q %q", cert, key)
	}

	cfg.System.Mgmt.TLSCertFile = "/cfg/server.crt"
	cfg.System.Mgmt.TLSKeyFile = "/cfg/server.key"
	cert, key = resolveTLSFiles(cfg)
	if cert != "/cfg/server.crt" || key != "/cfg/server.key" {
		t.Fatalf("config tls files = %q %q", cert, key)
	}

	t.Setenv("CONTAIND_TLS_CERT_FILE", "/env/server.crt")
	t.Setenv("CONTAIND_TLS_KEY_FILE", "/env/server.key")
	cert, key = resolveTLSFiles(cfg)
	if cert != "/env/server.crt" || key != "/env/server.key" {
		t.Fatalf("env tls files = %q %q", cert, key)
	}
}

func TestSecurityHeaderHandlers(t *testing.T) {
	t.Parallel()

	base := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	})

	t.Run("hsts on tls", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "https://example.invalid", nil)
		req.TLS = &tls.ConnectionState{}
		rec := httptest.NewRecorder()
		hstsHandler(true, 600, base).ServeHTTP(rec, req)
		if got := rec.Header().Get("Strict-Transport-Security"); got != "max-age=600" {
			t.Fatalf("hsts header = %q", got)
		}
	})

	t.Run("cors allow", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodOptions, "http://example.invalid", nil)
		req.Header.Set("Origin", "https://ui.example")
		rec := httptest.NewRecorder()
		corsHandler(base, []string{"https://ui.example"}).ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("cors status = %d, want 200", rec.Code)
		}
		if got := rec.Header().Get("Access-Control-Allow-Origin"); got != "https://ui.example" {
			t.Fatalf("cors allow origin = %q", got)
		}
	})

	t.Run("frame options csp", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "http://example.invalid", nil)
		rec := httptest.NewRecorder()
		frameOptionsHandler(base, []string{"https://ui.example"}).ServeHTTP(rec, req)
		if got := rec.Header().Get("Content-Security-Policy"); !strings.Contains(got, "frame-ancestors 'self' https://ui.example") {
			t.Fatalf("csp header = %q", got)
		}
	})
}

func TestGetAllowedOriginsAndRedirect(t *testing.T) {
	t.Setenv("CONTAIND_ALLOWED_ORIGINS", " https://ui.example, ,*,https://ops.example ")
	origins := getAllowedOrigins()
	if len(origins) != 2 || origins[0] != "https://ui.example" || origins[1] != "https://ops.example" {
		t.Fatalf("origins = %#v", origins)
	}

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "http://example.invalid/api", nil)
	req.Host = "fw.example:8080"
	redirectToHTTPSHandler(":8443", http.NotFoundHandler()).ServeHTTP(rec, req)
	if rec.Code != http.StatusFound {
		t.Fatalf("redirect status = %d, want 302", rec.Code)
	}
	if got := rec.Header().Get("Location"); got != "https://fw.example:8443/api" {
		t.Fatalf("redirect location = %q", got)
	}
}
