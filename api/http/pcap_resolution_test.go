// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

package httpapi

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"

	"github.com/tonylturner/containd/pkg/cp/config"
	"github.com/tonylturner/containd/pkg/dp/pcap"
)

func TestResolvePCAPConfigExpandsLogicalInterfacesAndZones(t *testing.T) {
	engine := &mockEngine{state: []config.InterfaceState{{Name: "eth0"}, {Name: "eth1"}}}
	running := config.Config{
		Zones: []config.Zone{{Name: "lan"}},
		Interfaces: []config.Interface{
			{Name: "lan1", Device: "eth0", Zone: "lan"},
			{Name: "lan2", Device: "eth1", Zone: "lan"},
		},
	}
	capture := config.PCAPConfig{
		Interfaces: []string{"lan1", "eth0"},
		Zones:      []string{"lan"},
		Filter:     config.PCAPFilter{Port: "2404"},
	}

	got, err := resolvePCAPConfig(context.Background(), engine, running, capture)
	if err != nil {
		t.Fatalf("resolvePCAPConfig: %v", err)
	}
	if !reflect.DeepEqual(got.Interfaces, []string{"eth0", "eth1"}) {
		t.Fatalf("resolved interfaces = %#v", got.Interfaces)
	}
	if len(got.Zones) != 0 || got.Filter.Port != "2404" {
		t.Fatalf("resolved config did not preserve filter or remove zone refs: %#v", got)
	}
}

func TestPCAPStartUsesBodyAndResolvesZoneAndPort(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.Interfaces[0].Device = "eth0"
	store := &mockStore{cfg: cfg}
	engine := newRuntimeMockEngine()
	engine.state = []config.InterfaceState{{Name: "eth0", Index: 1}}
	engine.pcapStatusResp = pcap.Status{Running: false}
	server := NewServerWithEngine(store, nil, engine)

	req := authedRequest(http.MethodPost, "/api/v1/pcap/start", bytes.NewBufferString(
		`{"interfaces":["wan"],"zones":["wan"],"filter":{"proto":"tcp","port":"2404"},"mode":"once"}`,
	))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	server.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("pcap start: status=%d body=%s", rec.Code, rec.Body.String())
	}
	if !reflect.DeepEqual(engine.pcapStartCfg.Interfaces, []string{"eth0"}) {
		t.Fatalf("engine interfaces = %#v, want resolved eth0", engine.pcapStartCfg.Interfaces)
	}
	if len(engine.pcapStartCfg.Zones) != 0 || engine.pcapStartCfg.Filter.Port != "2404" {
		t.Fatalf("engine capture config = %#v", engine.pcapStartCfg)
	}
	if !store.cfg.PCAP.Enabled || store.cfg.PCAP.Filter.Port != "2404" {
		t.Fatalf("saved capture config = %#v", store.cfg.PCAP)
	}
}

func TestPCAPStartRejectsUnknownInterfaceBeforeSaving(t *testing.T) {
	store := &mockStore{cfg: config.DefaultConfig()}
	engine := newRuntimeMockEngine()
	engine.state = []config.InterfaceState{{Name: "eth0", Index: 1}}
	server := NewServerWithEngine(store, nil, engine)

	req := authedRequest(http.MethodPost, "/api/v1/pcap/start", bytes.NewBufferString(
		`{"interfaces":["missing"]}`,
	))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	server.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "missing") {
		t.Fatalf("pcap start: status=%d body=%s", rec.Code, rec.Body.String())
	}
	if store.calls != 0 {
		t.Fatal("invalid capture selection reached config storage")
	}
}

func TestResolvePCAPConfigReportsUnresolvedReferences(t *testing.T) {
	engine := &mockEngine{state: []config.InterfaceState{{Name: "eth0"}}}
	running := config.Config{
		Zones:      []config.Zone{{Name: "empty"}},
		Interfaces: []config.Interface{{Name: "lan", Device: "eth0", Zone: "lan"}},
	}
	tests := []struct {
		name    string
		capture config.PCAPConfig
		want    string
	}{
		{name: "unknown logical or kernel", capture: config.PCAPConfig{Interfaces: []string{"missing"}}, want: `"missing"`},
		{name: "unknown zone", capture: config.PCAPConfig{Zones: []string{"missing"}}, want: `"missing"`},
		{name: "zone without interfaces", capture: config.PCAPConfig{Zones: []string{"empty"}}, want: `"empty"`},
		{name: "empty selection", capture: config.PCAPConfig{}, want: "at least one"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := resolvePCAPConfig(context.Background(), engine, running, tt.capture)
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("resolvePCAPConfig error = %v, want substring %q", err, tt.want)
			}
		})
	}
}
