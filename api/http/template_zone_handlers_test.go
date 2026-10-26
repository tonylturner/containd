// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

package httpapi

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/tonylturner/containd/pkg/cp/config"
)

func TestTemplateHandlers(t *testing.T) {
	store := &mockStore{cfg: config.DefaultConfig()}
	s := NewServerWithEngineAndServices(store, nil, nil, nil, nil)

	rec := httptest.NewRecorder()
	req := authedRequest(http.MethodGet, "/api/v1/templates", nil)
	s.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "maintenance-window") {
		t.Fatalf("templates list: expected built-in template payload, got %d body=%s", rec.Code, rec.Body.String())
	}

	rec = httptest.NewRecorder()
	req = authedRequest(http.MethodPost, "/api/v1/templates/apply", bytes.NewBufferString(`{"name":"modbus-read-only"}`))
	req.Header.Set("Content-Type", "application/json")
	s.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"applied":"modbus-read-only"`) {
		t.Fatalf("template apply: expected success payload, got %d body=%s", rec.Code, rec.Body.String())
	}
	if len(store.cfg.Firewall.Rules) == 0 {
		t.Fatalf("template apply did not persist rules")
	}
}

func TestZoneListDeleteAndPatchHandlers(t *testing.T) {
	store := &mockStore{cfg: &config.Config{
		Zones: []config.Zone{
			{Name: "ot"},
			{Name: "dmz"},
			{Name: "spare"},
			{Name: "wan"},
		},
		Interfaces: []config.Interface{
			{Name: "lan1", Zone: "ot"},
		},
		Firewall: config.FirewallConfig{
			Rules: []config.Rule{{
				ID:          "r1",
				SourceZones: []string{"dmz"},
				DestZones:   []string{"wan"},
				Action:      config.ActionAllow,
			}},
		},
	}}
	s := NewServer(store, nil)

	rec := httptest.NewRecorder()
	req := authedRequest(http.MethodGet, "/api/v1/zones", nil)
	s.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"spare"`) {
		t.Fatalf("zones list: expected zone payload, got %d body=%s", rec.Code, rec.Body.String())
	}

	rec = httptest.NewRecorder()
	req = authedRequest(http.MethodDelete, "/api/v1/zones/ot", nil)
	s.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "zone in use by interface") {
		t.Fatalf("zone delete interface-use: expected 400, got %d body=%s", rec.Code, rec.Body.String())
	}

	rec = httptest.NewRecorder()
	req = authedRequest(http.MethodDelete, "/api/v1/zones/dmz", nil)
	s.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "zone in use by firewall rule") {
		t.Fatalf("zone delete rule-use: expected 400, got %d body=%s", rec.Code, rec.Body.String())
	}

	rec = httptest.NewRecorder()
	req = authedRequest(http.MethodDelete, "/api/v1/zones/missing", nil)
	s.ServeHTTP(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("zone delete missing: expected 404, got %d body=%s", rec.Code, rec.Body.String())
	}

	rec = httptest.NewRecorder()
	req = authedRequest(http.MethodPatch, "/api/v1/zones/spare", bytes.NewBufferString(`{"alias":"plant","slTarget":2,"slOverrides":{"SR_1":true},"description":"updated"}`))
	req.Header.Set("Content-Type", "application/json")
	s.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("zone patch: expected 200, got %d body=%s", rec.Code, rec.Body.String())
	}
	zone := store.cfg.Zones[2]
	if zone.Alias != "plant" || zone.SLTarget != 2 || zone.Description != "updated" || !zone.SLOverrides["SR_1"] {
		t.Fatalf("zone patch not applied: %+v", zone)
	}

	rec = httptest.NewRecorder()
	req = authedRequest(http.MethodDelete, "/api/v1/zones/spare", nil)
	s.ServeHTTP(rec, req)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("zone delete success: expected 204, got %d body=%s", rec.Code, rec.Body.String())
	}
	if len(store.cfg.Zones) != 3 {
		t.Fatalf("zone delete did not persist removal: %+v", store.cfg.Zones)
	}
}
