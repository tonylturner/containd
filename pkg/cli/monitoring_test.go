// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 containd Authors

package cli

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"strings"
	"testing"

	"github.com/tonylturner/containd/pkg/cp/config"
)

func TestMonitoringShowUnavailable(t *testing.T) {
	for _, tc := range []struct {
		name, method, path string
		command            func(*API) Command
	}{
		{"flows", "GET", "/api/v1/flows", showFlows},
		{"protocols", "GET", "/api/v1/stats/protocols", showStatsProtocols},
		{"top-talkers", "GET", "/api/v1/stats/top-talkers", showStatsTopTalkers},
		{"anomalies", "GET", "/api/v1/anomalies", showAnomalies},
		{"signatures", "GET", "/api/v1/signatures", showSignaturesAPI},
		{"matches", "GET", "/api/v1/signatures/matches", showSignatureMatchesAPI},
		{"interfaces", "GET", "/api/v1/interfaces/state", showInterfacesStateAPI},
		{"listeners", "GET", "/api/v1/config", showMgmtListeners},
	} {
		t.Run(tc.name, func(t *testing.T) {
			for _, mode := range []string{"503", "transport", "malformed", "empty"} {
				t.Run(mode, func(t *testing.T) {
					client := &dispatchHTTPClient{t: t, handlers: map[string]func(*http.Request) (*http.Response, error){
						tc.method + " " + tc.path: func(*http.Request) (*http.Response, error) {
							switch mode {
							case "503":
								return jsonHTTPResponse(503, map[string]string{"error": "engine unavailable"}, nil), nil
							case "transport":
								return nil, errors.New("offline")
							case "malformed":
								return jsonHTTPResponse(200, "not an array or config", nil), nil
							default:
								if tc.name == "listeners" {
									return jsonHTTPResponse(200, map[string]any{}, nil), nil
								}
								return jsonHTTPResponse(200, []any{}, nil), nil
							}
						},
					}}
					var out bytes.Buffer
					err := tc.command(&API{BaseURL: "http://test", Client: client})(context.Background(), &out, nil)
					if mode == "empty" {
						if err != nil || strings.Contains(out.String(), "unavailable") {
							t.Fatalf("empty: %s (%v)", &out, err)
						}
					} else if err == nil || !strings.Contains(out.String(), "unavailable (state unknown)") || strings.Contains(out.String(), "No ") {
						t.Fatalf("failure: %s (%v)", &out, err)
					}
				})
			}
		})
	}
}

func TestShowSystemPartialUnavailable(t *testing.T) {
	for _, healthOK := range []bool{false, true} {
		for _, configOK := range []bool{false, true} {
			client := &dispatchHTTPClient{t: t, handlers: map[string]func(*http.Request) (*http.Response, error){
				"GET /api/v1/health": func(*http.Request) (*http.Response, error) {
					if !healthOK {
						return jsonHTTPResponse(503, map[string]string{}, nil), nil
					}
					return jsonHTTPResponse(200, map[string]string{"component": "mgmt"}, nil), nil
				},
				"GET /api/v1/config": func(*http.Request) (*http.Response, error) {
					if !configOK {
						return nil, errors.New("offline")
					}
					return jsonHTTPResponse(200, map[string]any{"system": map[string]string{"hostname": "real-host"}}, nil), nil
				},
			}}
			var out bytes.Buffer
			err := showSystem(shellModeStore(t, config.SSHRuntimePolicy{ShellMode: "appliance", ShellModeSource: "default"}), &API{BaseURL: "http://test", Client: client})(context.Background(), &out, nil)
			if (err != nil) != (!healthOK || !configOK) {
				t.Fatalf("error: %v", err)
			}
			for text, want := range map[string]bool{"System health unavailable": !healthOK, "System configuration unavailable": !configOK, "hostname: real-host": configOK, "component: mgmt": healthOK, "mgmt.http_enabled:": configOK, "ssh.shell_mode: appliance": configOK} {
				if strings.Contains(out.String(), text) != want {
					t.Fatalf("health=%v config=%v missing/unexpected %q: %s", healthOK, configOK, text, &out)
				}
			}
		}
	}
}

func TestShowInterfacesDoesNotSubstituteLocalState(t *testing.T) {
	client := &dispatchHTTPClient{t: t, handlers: map[string]func(*http.Request) (*http.Response, error){
		"GET /api/v1/interfaces": func(*http.Request) (*http.Response, error) {
			return jsonHTTPResponse(200, []map[string]string{{"name": "lan", "device": "lo0"}}, nil), nil
		},
		"GET /api/v1/interfaces/state": func(*http.Request) (*http.Response, error) {
			return jsonHTTPResponse(503, map[string]string{"error": "engine unavailable"}, nil), nil
		},
	}}
	var out bytes.Buffer
	err := showInterfacesAPI(&API{BaseURL: "http://test", Client: client})(context.Background(), &out, nil)
	if err == nil || !strings.Contains(out.String(), "Interface runtime state unavailable") || strings.Contains(out.String(), "127.0.0.1") {
		t.Fatalf("output: %s (%v)", &out, err)
	}
}

func TestSavedListenerViewsHSTS(t *testing.T) {
	off, on := false, true
	for _, view := range []struct {
		name    string
		command func(*API) Command
		key     string
	}{
		{"system", applianceShowSystem(t), "mgmt.hsts:"},
		{"listeners", showMgmtListeners, "hsts"},
	} {
		for _, tc := range []struct {
			name  string
			value *bool
			want  string
		}{
			{"unset uses runtime default", nil, "yes"},
			{"explicitly disabled", &off, "no"},
			{"explicitly enabled", &on, "yes"},
		} {
			t.Run(view.name+"/"+tc.name, func(t *testing.T) {
				cfg := config.Config{System: config.SystemConfig{Mgmt: config.MgmtConfig{EnableHSTS: tc.value}}}
				client := &dispatchHTTPClient{t: t, handlers: map[string]func(*http.Request) (*http.Response, error){
					"GET /api/v1/config": func(*http.Request) (*http.Response, error) { return jsonHTTPResponse(200, cfg, nil), nil },
					"GET /api/v1/health": func(*http.Request) (*http.Response, error) {
						return jsonHTTPResponse(200, map[string]string{"component": "mgmt"}, nil), nil
					},
				}}
				var out bytes.Buffer
				if err := view.command(&API{BaseURL: "http://test", Client: client})(context.Background(), &out, nil); err != nil {
					t.Fatal(err)
				}
				if !strings.Contains(out.String(), savedListenerNotice) {
					t.Fatalf("saved/live label missing: %s", &out)
				}
				found := false
				for _, line := range strings.Split(out.String(), "\n") {
					fields := strings.Fields(line)
					if len(fields) == 2 && fields[0] == view.key {
						found = true
						if fields[1] != tc.want {
							t.Fatalf("HSTS: %s, want %s", line, tc.want)
						}
					}
				}
				if !found {
					t.Fatalf("HSTS field missing: %s", &out)
				}
			})
		}
	}
}
