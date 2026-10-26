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
