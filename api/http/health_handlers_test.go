// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	engineclient "github.com/tonylturner/containd/api/engine"
	"github.com/tonylturner/containd/pkg/cp/config"
	dpengine "github.com/tonylturner/containd/pkg/dp/engine"
	"github.com/tonylturner/containd/pkg/dp/netcfg"
)

func TestHealthReportsUnboundManagement(t *testing.T) {
	cfg := config.DefaultConfig()
	engine := &mockEngine{}
	server := NewServerWithEngine(&mockStore{cfg: cfg}, nil, engine)
	check := func(want string) {
		t.Helper()
		rec := httptest.NewRecorder()
		server.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/v1/health", nil))
		var body struct {
			Binding struct {
				State string `json:"state"`
				Ports []int  `json:"recoveryPorts"`
			} `json:"managementBinding"`
		}
		if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
			t.Fatal(err)
		}
		if rec.Code != 200 || body.Binding.State != want || (want == "unbound-appliance" && len(body.Binding.Ports) == 0) {
			t.Fatalf("health = %s", rec.Body)
		}
	}
	check("unbound-appliance")
	cfg.Interfaces[0].Device = "eth0"
	check("configured")
	engine.state = []config.InterfaceState{{Name: "eth0", Up: false}, {Name: "eth1", Up: true}}
	check("configured") // Administrative link-down is not an unbound appliance.
	off := false
	for i := range cfg.Interfaces {
		cfg.Interfaces[i].Access = config.InterfaceAccess{Mgmt: &off, HTTP: &off, HTTPS: &off, SSH: &off}
	}
	check("configured")
}

type healthMockEngine struct {
	*mockEngine
	st         dpengine.IEC104Enforcement
	forwarding netcfg.IPv4ForwardingStatus
	err        error
}

func (m *healthMockEngine) RuntimeHealth(context.Context) (engineclient.RuntimeHealth, error) {
	return engineclient.RuntimeHealth{
		IEC104Enforcement: m.st,
		IPv4Forwarding:    m.forwarding,
	}, m.err
}

func healthBody(t *testing.T, engine EngineClient) (int, map[string]any) {
	t.Helper()
	s := NewServerWithEngine(&mockStore{}, nil, engine)
	rec := httptest.NewRecorder()
	req, _ := http.NewRequest(http.MethodGet, "/api/v1/health", nil)
	s.ServeHTTP(rec, req)
	var body map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
	return rec.Code, body
}

func TestHealthReportsIEC104Enforcement(t *testing.T) {
	cases := []struct {
		name       string
		engine     EngineClient
		want       map[string]any
		forwarding netcfg.IPv4ForwardingStatus
	}{
		{
			name:       "no engine",
			forwarding: netcfg.IPv4ForwardingUnknown,
			want:       map[string]any{"active": false, "healthy": false, "reason": "engine unreachable"},
		},
		{
			name:       "engine error",
			engine:     &healthMockEngine{mockEngine: &mockEngine{}, err: errors.New("connection refused")},
			forwarding: netcfg.IPv4ForwardingUnknown,
			want:       map[string]any{"active": false, "healthy": false, "reason": "engine unreachable"},
		},
		{
			name:       "engine unhealthy",
			engine:     &healthMockEngine{mockEngine: &mockEngine{}, st: dpengine.IEC104Enforcement{Active: true, Reason: "reset injector unavailable"}},
			forwarding: netcfg.IPv4ForwardingUnknown,
			want:       map[string]any{"active": true, "healthy": false, "reason": "reset injector unavailable"},
		},
		{
			name:       "inactive",
			engine:     &healthMockEngine{mockEngine: &mockEngine{}, st: dpengine.IEC104Enforcement{Healthy: true}},
			forwarding: netcfg.IPv4ForwardingUnknown,
			want:       map[string]any{"active": false, "healthy": true, "reason": ""},
		},
		{
			name:       "forwarding enabled",
			engine:     &healthMockEngine{mockEngine: &mockEngine{}, forwarding: netcfg.IPv4ForwardingEnabled},
			forwarding: netcfg.IPv4ForwardingEnabled,
			want:       map[string]any{"active": false, "healthy": false, "reason": ""},
		},
		{
			name:       "forwarding disabled",
			engine:     &healthMockEngine{mockEngine: &mockEngine{}, forwarding: netcfg.IPv4ForwardingDisabled},
			forwarding: netcfg.IPv4ForwardingDisabled,
			want:       map[string]any{"active": false, "healthy": false, "reason": ""},
		},
	}
	for _, c := range cases {
		code, body := healthBody(t, c.engine)
		if code != http.StatusOK || body["status"] != "ok" {
			t.Fatalf("%s: liveness = %d %v", c.name, code, body)
		}
		got, _ := body["iec104Enforcement"].(map[string]any)
		for k, v := range c.want {
			if got[k] != v {
				t.Fatalf("%s: iec104Enforcement = %v, want %v", c.name, got, c.want)
			}
		}
		if body["ipv4Forwarding"] != string(c.forwarding) {
			t.Fatalf("%s: ipv4Forwarding = %v, want %q", c.name, body["ipv4Forwarding"], c.forwarding)
		}
	}
}
