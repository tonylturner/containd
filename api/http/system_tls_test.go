// SPDX-License-Identifier: Apache-2.0

package httpapi

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/tonylturner/containd/pkg/cp/config"
)

func TestTLSUploadPathRefusal(t *testing.T) {
	certPEM, keyPEM := generateTestCertPEM(t)
	body, err := json.Marshal(setTLSCertRequest{CertPEM: certPEM, KeyPEM: keyPEM})
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name, source, kind string
		env                bool
	}{
		{"environment certificate", "CONTAIND_TLS_CERT_FILE", "certificate", true},
		{"environment key", "CONTAIND_TLS_KEY_FILE", "key", true},
		{"configured certificate", "system.mgmt.tlsCertFile", "certificate", false},
		{"configured key", "system.mgmt.tlsKeyFile", "key", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("CONTAIND_TLS_CERT_FILE", "")
			t.Setenv("CONTAIND_TLS_KEY_FILE", "")
			// Neither the refused file nor the other member may be touched.
			dir := t.TempDir()
			path := filepath.Join(dir, "outside.pem")
			const original = "unchanged"
			if err := os.WriteFile(path, []byte(original), 0o600); err != nil {
				t.Fatal(err)
			}
			cfg := config.DefaultConfig()
			cfg.System.Mgmt.TLSCertFile = ""
			cfg.System.Mgmt.TLSKeyFile = ""
			if tc.env {
				// An in-bound config value must not mask an env override.
				cfg.System.Mgmt.TLSCertFile = "/data/unused-cert.pem"
				cfg.System.Mgmt.TLSKeyFile = "/data/unused-key.pem"
				t.Setenv(tc.source, " "+path+" ")
			} else if tc.kind == "certificate" {
				cfg.System.Mgmt.TLSCertFile = " " + path + " "
			} else {
				cfg.System.Mgmt.TLSKeyFile = " " + path + " "
			}
			router := gin.New()
			router.POST("/upload", setTLSCertHandler(&mockStore{cfg: cfg}))
			rec := httptest.NewRecorder()
			router.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/upload", bytes.NewReader(body)))
			var resp struct {
				Error string `json:"error"`
			}
			if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
				t.Fatal(err)
			}
			want := fmt.Sprintf("TLS %s path %q (source: %s) must be under /data", tc.kind, path, tc.source)
			if rec.Code != http.StatusConflict || resp.Error != want {
				t.Fatalf("got %d %s; want 409 %q", rec.Code, rec.Body.String(), want)
			}
			got, err := os.ReadFile(path)
			if err != nil || string(got) != original {
				t.Fatalf("refused upload changed file: %q, %v", got, err)
			}
		})
	}
}

// recordServed records what the bound listeners serve until the test ends.
func recordServed(t *testing.T, served ServedManagement) {
	t.Helper()
	SetServedManagement(served)
	t.Cleanup(func() { SetServedManagement(ServedManagement{}) })
}

// An upload writes the files the saved settings name. It is served at once
// only when the bound HTTPS listener serves those files; after a listener
// fallback, or with HTTPS off, it waits for the next start and says so.
func TestTLSUploadSaysWhenItTakesEffect(t *testing.T) {
	certPEM, keyPEM := generateTestCertPEM(t)
	body, err := json.Marshal(setTLSCertRequest{CertPEM: certPEM, KeyPEM: keyPEM})
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("CONTAIND_TLS_CERT_FILE", "")
	t.Setenv("CONTAIND_TLS_KEY_FILE", "")
	for _, tc := range []struct {
		name          string
		served        func(dir string) ServedManagement
		code          int
		status, warns string
	}{
		{"served files", func(dir string) ServedManagement {
			return ServedManagement{CertFile: filepath.Join(dir, "tls", "saved.crt"), KeyFile: filepath.Join(dir, "tls", "saved.key")}
		}, http.StatusOK, "updated", ""},
		{"fallback files", func(dir string) ServedManagement {
			return ServedManagement{CertFile: filepath.Join(dir, "tls", "server.crt"), KeyFile: filepath.Join(dir, "tls", "server.key")}
		}, http.StatusOK, "stored", "the certificate is served from the next management start"},
		{"no HTTPS listener", func(string) ServedManagement { return ServedManagement{} },
			http.StatusOK, "stored", "no HTTPS listener is bound"},
		{"served certificate with another key", func(dir string) ServedManagement {
			return ServedManagement{CertFile: filepath.Join(dir, "tls", "saved.crt"), KeyFile: filepath.Join(dir, "tls", "server.key")}
		}, http.StatusConflict, "", ""},
		{"served key with another certificate", func(dir string) ServedManagement {
			return ServedManagement{CertFile: filepath.Join(dir, "tls", "server.crt"), KeyFile: filepath.Join(dir, "tls", "saved.key")}
		}, http.StatusConflict, "", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			served := tc.served(dir)
			recordServed(t, served)
			cfg := config.DefaultConfig()
			cfg.System.Mgmt.TLSCertFile = filepath.Join(dir, "tls", "saved.crt")
			cfg.System.Mgmt.TLSKeyFile = filepath.Join(dir, "tls", "saved.key")
			router := gin.New()
			router.POST("/upload", tlsCertUploadHandler(&mockStore{cfg: cfg}, dir))
			rec := httptest.NewRecorder()
			router.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/upload", bytes.NewReader(body)))
			if rec.Code != tc.code {
				t.Fatalf("status %d, body %s", rec.Code, rec.Body)
			}
			written, err := os.ReadFile(cfg.System.Mgmt.TLSCertFile)
			if tc.code == http.StatusConflict {
				if err == nil || !strings.Contains(rec.Body.String(), "would pair a new file with a served one") {
					t.Fatalf("refused upload wrote %q (%v): %s", written, err, rec.Body)
				}
				return
			}
			if err != nil || strings.TrimSpace(string(written)) != strings.TrimSpace(certPEM) {
				t.Fatalf("certificate not written: %v", err)
			}
			var resp struct {
				Status   string   `json:"status"`
				Warnings []string `json:"warnings"`
			}
			if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
				t.Fatal(err)
			}
			header := rec.Header().Values("X-Containd-Warnings")
			if resp.Status != tc.status || (tc.warns == "") != (len(resp.Warnings) == 0) || len(header) != len(resp.Warnings) {
				t.Fatalf("response %+v, header %q", resp, header)
			}
			if tc.warns != "" && (!strings.Contains(resp.Warnings[0], tc.warns) || served.CertFile != "" && !strings.Contains(resp.Warnings[0], served.CertFile)) {
				t.Fatalf("warning %q does not say when the upload is served", resp.Warnings[0])
			}
			if served.CertFile != "" && served.CertFile != cfg.System.Mgmt.TLSCertFile {
				if _, err := os.Stat(served.CertFile); !os.IsNotExist(err) {
					t.Fatalf("upload touched the served fallback certificate: %v", err)
				}
			}
		})
	}
}

// The readout names the files and certificate the bound HTTPS listener
// serves, and the listeners management has bound, next to the ones the
// next start serves, which a listener fallback or a later save makes
// differ. Paths are cleaned, so equal strings name the same file.
func TestTLSInfoShowsServedCertificate(t *testing.T) {
	t.Setenv("CONTAIND_TLS_CERT_FILE", "")
	t.Setenv("CONTAIND_TLS_KEY_FILE", "")
	t.Setenv(config.EnvManagementHTTPAddr, "")
	t.Setenv(config.EnvManagementHTTPSAddr, "")
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, "tls"), 0o755); err != nil {
		t.Fatal(err)
	}
	savedPEM, _ := generateTestCertPEM(t)
	_, servedPEM := consoleTestCertificate(t)
	savedCert, servedCert := filepath.Join(dir, "tls", "saved.crt"), filepath.Join(dir, "tls", "server.crt")
	if err := os.WriteFile(savedCert, []byte(savedPEM), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(servedCert, servedPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	cfg := config.DefaultConfig()
	cfg.System.Mgmt.HTTPSListenAddr = ":9443"
	cfg.System.Mgmt.TLSCertFile = dir + "/tls/./saved.crt"
	cfg.System.Mgmt.TLSKeyFile = dir + "//tls/saved.key"
	read := func() tlsInfoResponse {
		t.Helper()
		router := gin.New()
		router.GET("/tls", getTLSHandler(&mockStore{cfg: cfg}))
		rec := httptest.NewRecorder()
		router.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/tls", nil))
		var got tlsInfoResponse
		if rec.Code != http.StatusOK {
			t.Fatalf("status %d", rec.Code)
		}
		if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
			t.Fatal(err)
		}
		return got
	}

	bindConsoleTest(t, config.ManagementListeners{
		HTTP:  config.ManagementListener{Addr: ":8080", Enabled: true},
		HTTPS: config.ManagementListener{Addr: ":8443", Enabled: true},
	})
	recordServed(t, ServedManagement{CertFile: dir + "/tls/../tls/server.crt", KeyFile: dir + "/tls/server.key/"})
	got := read()
	if got.CertFile != savedCert || got.KeyFile != filepath.Join(dir, "tls", "saved.key") ||
		got.ServedCertFile != servedCert || got.ServedKeyFile != filepath.Join(dir, "tls", "server.key") {
		t.Fatalf("fallback files = %+v", got)
	}
	if !strings.Contains(got.CertSubject, "containd.local") || got.CertNotAfter == "" ||
		!strings.Contains(got.ServedCertSubject, "appliance.example") || got.ServedCertNotAfter == "" || got.ServedCertNotAfter == got.CertNotAfter {
		t.Fatalf("certificates = %+v", got)
	}
	if got.BoundHTTPListenAddr != ":8080" || got.BoundHTTPSListenAddr != ":8443" || got.HTTPSListenAddr != ":9443" {
		t.Fatalf("listeners = %+v", got)
	}

	// The saved files served now name the same file however they are spelled.
	SetServedManagement(ServedManagement{CertFile: savedCert, KeyFile: filepath.Join(dir, "tls", "saved.key")})
	if got := read(); got.ServedCertFile != got.CertFile || got.ServedKeyFile != got.KeyFile || got.ServedCertSubject != got.CertSubject {
		t.Fatalf("served saved files = %+v", got)
	}

	bindConsoleTest(t, config.ManagementListeners{HTTP: config.ManagementListener{Addr: ":8080", Enabled: true}, HTTPS: config.ManagementListener{Addr: ":8443"}})
	SetServedManagement(ServedManagement{})
	if got := read(); got.ServedCertFile != "" || got.ServedKeyFile != "" || got.ServedCertSubject != "" || got.ServedCertNotAfter != "" ||
		got.BoundHTTPSListenAddr != "" || got.BoundHTTPListenAddr != ":8080" {
		t.Fatalf("readout without HTTPS = %+v", got)
	}
}
