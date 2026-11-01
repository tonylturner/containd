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
	"go.uber.org/zap"
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
	sshTestKeyPair(t, dir, "server")
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

// Startup never repairs or creates external identities, even under /data.
func TestTLSExternalStartupIsReadOnly(t *testing.T) {
	for _, kind := range []string{"bundle", "split", "mismatch", "missing"} {
		t.Run(kind, func(t *testing.T) {
			dir := t.TempDir()
			cert, key, err := selfSignedTLS(nil)
			if err != nil {
				t.Fatal(err)
			}
			c, k := filepath.Join(dir, "server.crt"), filepath.Join(dir, "server.key")
			if kind == "bundle" {
				c = filepath.Join(dir, "server.pem")
				k = c
				cert = append(cert, key...)
			}
			if kind == "mismatch" {
				_, key, err = selfSignedTLS(nil)
				if err != nil {
					t.Fatal(err)
				}
			}
			if kind != "missing" {
				if err := os.WriteFile(c, cert, 0o640); err != nil {
					t.Fatal(err)
				}
				if k != c {
					if err := os.WriteFile(k, key, 0o640); err != nil {
						t.Fatal(err)
					}
				}
			}
			t.Setenv("CONTAIND_TLS_CERT_FILE", c)
			t.Setenv("CONTAIND_TLS_KEY_FILE", k)
			cfg := config.DefaultConfig()
			cfg.System.Mgmt.EnableHTTPS = boolPtr(true)
			lc, err := resolveMgmtListenerConfig(zap.NewNop().Sugar(), cfg, nil)
			if err != nil {
				t.Fatal(err)
			}
			valid := kind == "bundle" || kind == "split"
			if lc.enableHTTPS != valid {
				t.Fatalf("HTTPS enabled=%v for %s", lc.enableHTTPS, kind)
			}
			if kind == "missing" {
				entries, err := os.ReadDir(dir)
				if err != nil || len(entries) != 0 {
					t.Fatal("created external identity")
				}
				return
			}
			for path, want := range map[string][]byte{c: cert} {
				got, err := os.ReadFile(path)
				if err != nil || !bytes.Equal(got, want) {
					t.Fatal("external bytes changed")
				}
				st, err := os.Stat(path)
				if err != nil || st.Mode().Perm() != 0o640 {
					t.Fatal("external permissions changed")
				}
			}
			if c != k {
				got, err := os.ReadFile(k)
				if err != nil || !bytes.Equal(got, key) {
					t.Fatal("external key changed")
				}
				st, err := os.Stat(k)
				if err != nil || st.Mode().Perm() != 0o640 {
					t.Fatal("external key permissions changed")
				}
			}
		})
	}
}
