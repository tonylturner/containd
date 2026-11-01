// SPDX-License-Identifier: Apache-2.0

package httpapi

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"

	"github.com/tonylturner/containd/pkg/common/mgmttls"
	"github.com/tonylturner/containd/pkg/cp/config"
)

func TestTLSInfoReportsManagedUploadMode(t *testing.T) {
	cert, key := generateTestCertPEM(t)
	body, err := json.Marshal(setTLSCertRequest{CertPEM: cert, KeyPEM: key})
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name, cfgCert, cfgKey, envCert, envKey string
		managed                                bool
	}{
		{name: "implicit defaults", managed: true},
		{name: "explicit legacy defaults", cfgCert: mgmttls.DefaultCertFile, cfgKey: mgmttls.DefaultKeyFile, managed: true},
		{name: "cleaned legacy defaults", cfgCert: "/data/tls/./server.crt", cfgKey: "/data/tls/../tls/server.key", managed: true},
		{name: "explicit external bundle at managed location", cfgCert: mgmttls.DefaultBundleFile, cfgKey: mgmttls.DefaultBundleFile},
		{name: "external certificate only", cfgCert: "/operator/cert.pem"},
		{name: "external environment override", envKey: "/operator/key.pem"},
		{name: "default environment overrides external config", cfgCert: "/operator/bundle.pem", cfgKey: "/operator/bundle.pem", envCert: mgmttls.DefaultCertFile, envKey: mgmttls.DefaultKeyFile, managed: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("CONTAIND_TLS_CERT_FILE", tc.envCert)
			t.Setenv("CONTAIND_TLS_KEY_FILE", tc.envKey)
			cfg := config.DefaultConfig()
			cfg.System.Mgmt.TLSCertFile = tc.cfgCert
			cfg.System.Mgmt.TLSKeyFile = tc.cfgKey
			// The bound listener's mode must not override the next-start
			// configuration's mode, even when their file paths coincide.
			servedPath := mgmttls.DefaultBundleFile
			if tc.managed {
				servedPath = "/operator/previous.pem"
			}
			recordServed(t, ServedManagement{CertFile: servedPath, KeyFile: servedPath})
			store := &mockStore{cfg: cfg}
			router := gin.New()
			router.GET("/tls", getTLSHandler(store))
			router.POST("/upload", tlsCertUploadHandler(store, t.TempDir()))
			rec := httptest.NewRecorder()
			router.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/tls", nil))
			var got struct {
				Managed  *bool  `json:"managed"`
				CertFile string `json:"certFile"`
				KeyFile  string `json:"keyFile"`
			}
			if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
				t.Fatal(err)
			}
			if rec.Code != http.StatusOK || got.Managed == nil || *got.Managed != tc.managed {
				t.Fatalf("status must explicitly report managed=%t: %d %s", tc.managed, rec.Code, rec.Body)
			}
			certFile, keyFile := mgmttls.IdentityFiles(cfg)
			if got.CertFile != cleanFilePath(certFile) || got.KeyFile != cleanFilePath(keyFile) {
				t.Fatalf("mode and next-start paths disagree: %+v", got)
			}
			rec = httptest.NewRecorder()
			router.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/upload", bytes.NewReader(body)))
			wantStatus := http.StatusConflict
			if tc.managed {
				wantStatus = http.StatusOK
			}
			if rec.Code != wantStatus {
				t.Fatalf("managed=%t disagrees with upload policy: %d %s", tc.managed, rec.Code, rec.Body)
			}
		})
	}
}

func TestTLSInfoReportsEffectiveListeners(t *testing.T) {
	disabled := false
	withSaved := config.DefaultConfig()
	withSaved.System.Mgmt.ListenAddr = ":7080"
	withSaved.System.Mgmt.HTTPListenAddr = ""
	withSaved.System.Mgmt.HTTPSListenAddr = ":7443"
	withSaved.System.Mgmt.EnableHTTPS = &disabled
	for _, tc := range []struct {
		name     string
		cfg      *config.Config
		httpEnv  string
		httpsEnv string
		want     tlsInfoResponse
	}{
		{
			name: "defaults",
			cfg:  &config.Config{},
			want: tlsInfoResponse{HTTPListenAddr: config.DefaultManagementHTTPAddr, HTTPSListenAddr: config.DefaultManagementHTTPSAddr, HTTPEnabled: true, HTTPSEnabled: true},
		},
		{
			name: "saved",
			cfg:  withSaved,
			want: tlsInfoResponse{HTTPListenAddr: ":7080", HTTPSListenAddr: ":7443", HTTPEnabled: true},
		},
		{
			name:     "environment",
			cfg:      withSaved,
			httpEnv:  "127.0.0.1:9180",
			httpsEnv: ":9543",
			want:     tlsInfoResponse{HTTPListenAddr: "127.0.0.1:9180", HTTPSListenAddr: ":9543", HTTPEnabled: true},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv(config.EnvManagementHTTPAddr, tc.httpEnv)
			t.Setenv(config.EnvManagementHTTPSAddr, tc.httpsEnv)
			router := gin.New()
			router.GET("/tls", getTLSHandler(&mockStore{cfg: tc.cfg}))
			rec := httptest.NewRecorder()
			router.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/tls", nil))
			var got tlsInfoResponse
			if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
				t.Fatal(err)
			}
			if rec.Code != http.StatusOK || got.HTTPListenAddr != tc.want.HTTPListenAddr || got.HTTPSListenAddr != tc.want.HTTPSListenAddr ||
				got.HTTPEnabled != tc.want.HTTPEnabled || got.HTTPSEnabled != tc.want.HTTPSEnabled {
				t.Fatalf("status=%d listeners=%+v, want %+v", rec.Code, got, tc.want)
			}
		})
	}
}
