// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

package cli

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"reflect"
	"strings"
	"testing"

	"github.com/tonylturner/containd/pkg/cp/config"
)

func TestSetDataPlanePreservesCandidateConfig(t *testing.T) {
	candidate := config.DataPlaneConfig{
		CaptureInterfaces: []string{"wan", "lan1"},
		Enforcement:       false,
		EnforceTable:      "candidate_table",
		DPIMock:           true,
		DPIEnabled:        true,
		DPIMode:           "enforce",
		DPIProtocols:      map[string]bool{"dns": false, "http": true},
		DPIICSProtocols:   map[string]bool{"modbus": false, "iec104": true},
		DPIICSParsing:     map[string]string{"modbus": "strict", "iec104": "tolerant"},
		DPIExclusions: []config.DPIExclusion{
			{Value: "192.0.2.0/24", Type: "cidr", Reason: "lab segment"},
		},
		NFLogGroup:   100,
		NFQueueGroup: 101,
	}

	tests := []struct {
		name       string
		value      string
		wantOn     bool
		table      string
		interfaces []string
	}{
		{name: "on", value: "on", wantOn: true},
		{name: "off", value: "off"},
		{name: "true alias", value: "true", wantOn: true},
		{name: "false alias", value: "false"},
		{name: "one alias", value: "1", wantOn: true},
		{name: "zero alias", value: "0"},
		{name: "table only", value: "on", wantOn: true, table: "new_table"},
		{
			name:       "explicit table and interfaces",
			value:      "on",
			wantOn:     true,
			table:      "new_table",
			interfaces: []string{"edge0", "edge1"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			requests := make([]string, 0, 2)
			client := &dispatchHTTPClient{
				t: t,
				handlers: map[string]func(*http.Request) (*http.Response, error){
					"GET /api/v1/dataplane": func(*http.Request) (*http.Response, error) {
						requests = append(requests, "GET /api/v1/dataplane")
						return jsonHTTPResponse(http.StatusOK, candidate, nil), nil
					},
					"POST /api/v1/dataplane": func(req *http.Request) (*http.Response, error) {
						requests = append(requests, "POST /api/v1/dataplane")
						got := decodeJSONRequest[config.DataPlaneConfig](t, req)
						want := candidate
						want.Enforcement = tt.wantOn
						if tt.table != "" {
							want.EnforceTable = tt.table
						}
						if tt.interfaces != nil {
							want.CaptureInterfaces = tt.interfaces
						}
						if !reflect.DeepEqual(got, want) {
							t.Errorf("posted dataplane config = %#v, want %#v", got, want)
						}
						return jsonHTTPResponse(http.StatusOK, nil, map[string]string{
							"X-Containd-Config": "staged",
						}), nil
					},
				},
			}
			api := &API{BaseURL: "http://localhost:8080", Client: client}
			var out bytes.Buffer
			args := []string{"enforcement", tt.value}
			if tt.table != "" {
				args = append(args, tt.table)
				args = append(args, tt.interfaces...)
			}
			if err := setDataPlaneAPI(api)(context.Background(), &out, args); err != nil {
				t.Fatalf("setDataPlaneAPI: %v", err)
			}
			if want := []string{"GET /api/v1/dataplane", "POST /api/v1/dataplane"}; !reflect.DeepEqual(requests, want) {
				t.Errorf("requests = %v, want %v (no commit request)", requests, want)
			}
			if !strings.Contains(out.String(), stagedMessage) {
				t.Errorf("output %q does not report staged config", out.String())
			}
		})
	}
}

func TestSetDataPlaneDoesNotPostAfterCandidateGetFailure(t *testing.T) {
	tests := []struct {
		name     string
		response func(*http.Request) (*http.Response, error)
	}{
		{
			name: "http status",
			response: func(*http.Request) (*http.Response, error) {
				return jsonHTTPResponse(http.StatusServiceUnavailable, nil, nil), nil
			},
		},
		{
			name: "transport error",
			response: func(*http.Request) (*http.Response, error) {
				return nil, errors.New("connection unavailable")
			},
		},
		{
			name: "decode error",
			response: func(*http.Request) (*http.Response, error) {
				return jsonHTTPResponse(http.StatusOK, `{"dpiEnabled":`, nil), nil
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			requests := make([]string, 0, 1)
			client := &dispatchHTTPClient{
				t: t,
				handlers: map[string]func(*http.Request) (*http.Response, error){
					"GET /api/v1/dataplane": func(req *http.Request) (*http.Response, error) {
						requests = append(requests, "GET /api/v1/dataplane")
						return tt.response(req)
					},
					"POST /api/v1/dataplane": func(*http.Request) (*http.Response, error) {
						requests = append(requests, "POST /api/v1/dataplane")
						return jsonHTTPResponse(http.StatusOK, nil, nil), nil
					},
				},
			}
			api := &API{BaseURL: "http://localhost:8080", Client: client}
			err := setDataPlaneAPI(api)(context.Background(), nil, []string{"enforcement", "on"})
			if err == nil {
				t.Fatal("setDataPlaneAPI succeeded after candidate GET failure")
			}
			if want := []string{"GET /api/v1/dataplane"}; !reflect.DeepEqual(requests, want) {
				t.Errorf("requests = %v, want %v; candidate must not be posted", requests, want)
			}
		})
	}
}

func TestSetDataPlaneRejectsInvalidEnforcementWithoutRequests(t *testing.T) {
	client := &dispatchHTTPClient{t: t, handlers: map[string]func(*http.Request) (*http.Response, error){}}
	api := &API{BaseURL: "http://localhost:8080", Client: client}

	err := setDataPlaneAPI(api)(context.Background(), nil, []string{"enforcement", "enabled"})
	if err == nil || !strings.Contains(err.Error(), "invalid enforcement value") {
		t.Fatalf("setDataPlaneAPI error = %v, want invalid enforcement value", err)
	}
}
