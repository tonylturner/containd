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

func TestSetDataPlaneLimits(t *testing.T) {
	for _, tc := range []struct {
		key, value string
		bad        bool
	}{
		{"maxFlows", "2048", false}, {"maxTopTalkers", "64", false}, {"maxInspectionBytes", "8388608", false},
		{"maxFlows", "0", false}, {"maxFlows", "1023", true}, {"maxTopTalkers", "262145", true},
		{"maxInspectionBytes", "-1", true}, {"maxFlows", "bad", true}, {"other", "10", true},
	} {
		t.Run(tc.key+tc.value, func(t *testing.T) {
			posted := false
			client := &dispatchHTTPClient{t: t, handlers: map[string]func(*http.Request) (*http.Response, error){
				"GET /api/v1/dataplane": func(*http.Request) (*http.Response, error) {
					return jsonHTTPResponse(200, map[string]any{"dpiEnabled": true, "limits": map[string]any{"maxTopTalkers": 128}}, map[string]string{"X-Containd-Revision": "0123456789abcdef.1"}), nil
				},
				"POST /api/v1/dataplane": func(req *http.Request) (*http.Response, error) {
					posted = true
					got := decodeJSONRequest[config.DataPlaneConfig](t, req)
					if !got.DPIEnabled || (tc.key != "maxTopTalkers" && got.Limits.MaxTopTalkers != 128) {
						t.Fatal(got)
					}
					if req.Header.Get("X-Containd-If-Revision") != "0123456789abcdef.1" {
						t.Fatal("missing revision")
					}
					return jsonHTTPResponse(200, got, map[string]string{"X-Containd-Config": "staged"}), nil
				},
			}}
			api := &API{BaseURL: "http://localhost", Client: client}
			err := setDataPlaneLimitsAPI(api)(context.Background(), nil, []string{tc.key, tc.value})
			if (err != nil) != tc.bad || posted == tc.bad {
				t.Fatalf("posted=%t err=%v", posted, err)
			}
		})
	}
}

func TestShowDataPlaneLimits(t *testing.T) {
	client := &dispatchHTTPClient{t: t, handlers: map[string]func(*http.Request) (*http.Response, error){
		"GET /api/v1/dataplane": func(*http.Request) (*http.Response, error) {
			return jsonHTTPResponse(200, config.DataPlaneConfig{Limits: config.DataPlaneLimits{MaxFlows: 2048}}, nil), nil
		},
	}}
	var out bytes.Buffer
	if err := showDataPlane(&API{BaseURL: "http://localhost", Client: client})(context.Background(), &out, nil); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"2048 effective (default 16384; stored 2048)", "8192 effective (default 8192; stored 0)", "67108864 effective"} {
		if !strings.Contains(out.String(), want) {
			t.Fatal(out.String())
		}
	}
}
