// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

package mgmtapp

import (
	"bytes"
	"crypto/tls"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

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

// The HTTPS listener serves a certificate replaced in place from its next
// handshake, which a certificate upload to the served files relies on.
func TestCertReloaderServesReplacedFiles(t *testing.T) {
	dir := t.TempDir()
	certFile, keyFile := filepath.Join(dir, "server.crt"), filepath.Join(dir, "server.key")
	reloader := newCertReloader(certFile, keyFile)
	served := func() []byte {
		t.Helper()
		cert, err := reloader.GetCertificate(nil)
		if err != nil {
			t.Fatal(err)
		}
		return cert.Certificate[0]
	}
	if _, _, err := ensureSelfSignedTLSFiles(certFile, keyFile, nil); err != nil {
		t.Fatal(err)
	}
	first := served()
	_, _, next := sshTestKeyPair(t, dir, "next")
	for _, name := range []string{"next.crt", "next.key"} {
		data, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			t.Fatal(err)
		}
		target := certFile
		if strings.HasSuffix(name, ".key") {
			target = keyFile
		}
		if err := os.WriteFile(target, data, 0o600); err != nil {
			t.Fatal(err)
		}
		// Filesystem timestamps can be coarse; the reloader compares them.
		later := time.Now().Add(time.Minute)
		if err := os.Chtimes(target, later, later); err != nil {
			t.Fatal(err)
		}
	}
	if got := served(); bytes.Equal(got, first) || !bytes.Equal(got, next.Certificate[0]) {
		t.Fatal("reloader kept serving the replaced certificate")
	}
}
