// SPDX-License-Identifier: Apache-2.0

package httpapi

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"

	"github.com/tonylturner/containd/pkg/cp/config"
)

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
			serveWithConfigRevision(t, router, rec, httptest.NewRequest(http.MethodGet, "/tls", nil))
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
