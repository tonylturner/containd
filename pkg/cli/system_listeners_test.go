// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/tonylturner/containd/pkg/cp/config"
)

func TestHTTPListenCommandsReplaceLegacySetting(t *testing.T) {
	for name, command := range map[string]func(*API) Command{
		"mgmt listen": setSystemMgmtListenAPI,
		"http listen": setSystemMgmtHTTPListenAPI,
	} {
		t.Run(name, func(t *testing.T) {
			cfg := config.DefaultConfig()
			cfg.System.Mgmt.HTTPListenAddr = ":8080"
			cfg.System.Mgmt.ListenAddr = ":7080"
			cfg.System.Mgmt.HTTPSListenAddr = ":8443"
			posted := false
			client := &dispatchHTTPClient{t: t, handlers: map[string]func(*http.Request) (*http.Response, error){
				"GET /api/v1/config/candidate": func(*http.Request) (*http.Response, error) {
					return jsonHTTPResponse(http.StatusOK, cfg, nil), nil
				},
				"POST /api/v1/config/candidate": func(req *http.Request) (*http.Response, error) {
					got := decodeJSONRequest[config.Config](t, req)
					posted = true
					if got.System.Mgmt.HTTPListenAddr != ":9080" || got.System.Mgmt.ListenAddr != "" {
						t.Fatalf("HTTP listener not replaced: %+v", got.System.Mgmt)
					}
					if got.System.Mgmt.HTTPSListenAddr != cfg.System.Mgmt.HTTPSListenAddr {
						t.Fatal("HTTPS listener changed")
					}
					if addr := savedListeners(&got).HTTP.Addr; addr != ":9080" {
						t.Fatalf("resolved HTTP listener = %q", addr)
					}
					return jsonHTTPResponse(http.StatusOK, nil, nil), nil
				},
			}}
			api := &API{BaseURL: "http://test", Client: client}
			if err := command(api)(context.Background(), io.Discard, []string{":9080"}); err != nil {
				t.Fatal(err)
			}
			if !posted {
				t.Fatal("no candidate was posted")
			}
		})
	}
}

// The saved listener views fill unset addresses with the resolver's
// defaults and never apply this client's environment.
func TestSavedListenerViewsResolveDefaults(t *testing.T) {
	t.Setenv(config.EnvManagementHTTPAddr, ":9180")
	t.Setenv(config.EnvSSHAddr, ":9222")
	for _, tc := range []struct {
		name string
		cfg  config.Config
		want []string
	}{
		{"unset", config.Config{}, []string{
			config.DefaultManagementHTTPAddr, config.DefaultManagementHTTPSAddr, config.DefaultSSHAddr,
		}},
		{"legacy listenAddr", config.Config{System: config.SystemConfig{Mgmt: config.MgmtConfig{ListenAddr: ":7080"}}}, []string{":7080"}},
	} {
		client := &dispatchHTTPClient{t: t, handlers: map[string]func(*http.Request) (*http.Response, error){
			"GET /api/v1/config": func(*http.Request) (*http.Response, error) { return jsonHTTPResponse(200, tc.cfg, nil), nil },
			"GET /api/v1/health": func(*http.Request) (*http.Response, error) {
				return jsonHTTPResponse(200, map[string]string{"component": "mgmt"}, nil), nil
			},
		}}
		api := &API{BaseURL: "http://test", Client: client}
		for name, command := range map[string]func(*API) Command{"system": applianceShowSystem(t), "listeners": showMgmtListeners} {
			var out bytes.Buffer
			if err := command(api)(context.Background(), &out, nil); err != nil {
				t.Fatal(err)
			}
			for _, want := range tc.want {
				if !strings.Contains(out.String(), want) {
					t.Errorf("%s/%s: missing %s: %s", tc.name, name, want, &out)
				}
			}
			if strings.Contains(out.String(), ":9180") || strings.Contains(out.String(), ":9222") {
				t.Errorf("%s/%s: client environment applied: %s", tc.name, name, &out)
			}
		}
	}
}
