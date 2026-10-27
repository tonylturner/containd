// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"bytes"
	"context"
	"net/http"
	"strings"
	"testing"

	"github.com/tonylturner/containd/pkg/cp/config"
)

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
		for name, command := range map[string]func(*API) Command{"system": showSystem, "listeners": showMgmtListeners} {
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
