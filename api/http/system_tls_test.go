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

// The readout names the files the bound HTTPS listener serves next to the
// files the saved settings name, which a listener fallback makes differ.
func TestTLSInfoShowsServedCertificate(t *testing.T) {
	t.Setenv("CONTAIND_TLS_CERT_FILE", "")
	t.Setenv("CONTAIND_TLS_KEY_FILE", "")
	cfg := config.DefaultConfig()
	cfg.System.Mgmt.TLSCertFile = "/data/tls/saved.crt"
	cfg.System.Mgmt.TLSKeyFile = "/data/tls/saved.key"
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
	recordServed(t, ServedManagement{CertFile: "/data/tls/server.crt", KeyFile: "/data/tls/server.key"})
	if got := read(); got.CertFile != "/data/tls/saved.crt" || got.KeyFile != "/data/tls/saved.key" ||
		got.ServedCertFile != "/data/tls/server.crt" || got.ServedKeyFile != "/data/tls/server.key" {
		t.Fatalf("fallback readout = %+v", got)
	}
	SetServedManagement(ServedManagement{})
	if got := read(); got.ServedCertFile != "" || got.ServedKeyFile != "" {
		t.Fatalf("readout without HTTPS = %+v", got)
	}
}
