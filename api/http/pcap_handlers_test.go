// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

package httpapi

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/tonylturner/containd/pkg/cp/config"
	"github.com/tonylturner/containd/pkg/dp/pcap"
)

type pcapStartErrorEngine struct {
	*runtimeMockEngine
	err error
}

func (e *pcapStartErrorEngine) StartPcap(context.Context, config.PCAPConfig) (pcap.Status, error) {
	return pcap.Status{}, e.err
}

func TestPCAPStartForwardsOverrideBodyToEngine(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.PCAP.Interfaces = []string{"stored"}
	store := &mockStore{cfg: cfg}
	engine := newRuntimeMockEngine()
	server := NewServerWithEngine(store, nil, engine)

	rec := httptest.NewRecorder()
	req := authedRequest(http.MethodPost, "/api/v1/pcap/start", strings.NewReader(
		`{"interfaces":["override"],"zones":["lab"],"filter":{"port":"2404"}}`,
	))
	server.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("pcap start status = %d body=%s", rec.Code, rec.Body.String())
	}
	if got := engine.pcapStartCfg; len(got.Interfaces) != 1 || got.Interfaces[0] != "override" {
		t.Fatalf("engine start interfaces = %#v, want override body value", got.Interfaces)
	}
	if got := engine.pcapStartCfg.Zones; len(got) != 1 || got[0] != "lab" {
		t.Fatalf("engine start zones = %#v, want override body value", got)
	}
	if engine.pcapStartCfg.Filter.Port != "2404" {
		t.Fatalf("engine start port = %q, want 2404", engine.pcapStartCfg.Filter.Port)
	}
}

func TestPCAPStartMapsEngineResolutionErrorToBadRequest(t *testing.T) {
	store := &mockStore{cfg: config.DefaultConfig()}
	engine := &pcapStartErrorEngine{
		runtimeMockEngine: newRuntimeMockEngine(),
		err:               errors.New(`pcap zone "ghost" has no configured interfaces`),
	}
	server := NewServerWithEngine(store, nil, engine)

	rec := httptest.NewRecorder()
	req := authedRequest(http.MethodPost, "/api/v1/pcap/start", strings.NewReader(
		`{"zones":["ghost"]}`,
	))
	server.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("pcap start status = %d body=%s, want 400", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "ghost") {
		t.Fatalf("pcap start response did not name unknown zone: %s", rec.Body.String())
	}
}
