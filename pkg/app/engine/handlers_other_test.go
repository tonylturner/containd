// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

//go:build !linux

package engineapp

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"go.uber.org/zap"

	"github.com/tonylturner/containd/pkg/cp/config"
)

func TestUnsupportedPlatformHandlers(t *testing.T) {
	t.Parallel()

	logger := zap.NewNop().Sugar()
	ownership := newOwnershipManager(logger)

	t.Run("interfaces apply", func(t *testing.T) {
		payload := []config.Interface{{Name: "wan", Device: "eth0", Zone: "wan"}}
		raw, _ := json.Marshal(payload)

		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/internal/interfaces?mode=replace", bytes.NewReader(raw))
		interfacesHandler(logger, ownership).ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("interfaces POST status = %d body=%s", rec.Code, rec.Body.String())
		}

		rec = httptest.NewRecorder()
		req = httptest.NewRequest(http.MethodPost, "/internal/interfaces", bytes.NewBufferString("{"))
		interfacesHandler(logger, ownership).ServeHTTP(rec, req)
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("interfaces invalid JSON status = %d", rec.Code)
		}
	})

	t.Run("routing apply", func(t *testing.T) {
		payload := config.RoutingConfig{
			Routes: []config.StaticRoute{{Dst: "default", Gateway: "10.0.0.1", Iface: "wan"}},
			Rules:  []config.PolicyRule{{Table: 100, Src: "10.0.0.0/24"}},
		}
		raw, _ := json.Marshal(payload)

		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/internal/routing?mode=replace", bytes.NewReader(raw))
		routingHandler(logger, ownership).ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("routing POST status = %d body=%s", rec.Code, rec.Body.String())
		}

		rec = httptest.NewRecorder()
		req = httptest.NewRequest(http.MethodPost, "/internal/routing", bytes.NewBufferString("{"))
		routingHandler(logger, ownership).ServeHTTP(rec, req)
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("routing invalid JSON status = %d", rec.Code)
		}
	})

	t.Run("wireguard status", func(t *testing.T) {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/internal/wireguard/status?iface=wg-lab", nil)
		wireguardStatusHandler().ServeHTTP(rec, req)
		if rec.Code != http.StatusNotImplemented {
			t.Fatalf("wireguard status code = %d", rec.Code)
		}
		if !strings.Contains(rec.Body.String(), "not supported") {
			t.Fatalf("unexpected wireguard status body: %q", rec.Body.String())
		}
	})

	t.Run("conntrack", func(t *testing.T) {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/internal/conntrack?limit=5", nil)
		conntrackHandler().ServeHTTP(rec, req)
		if rec.Code != http.StatusServiceUnavailable {
			t.Fatalf("conntrack list status = %d", rec.Code)
		}

		rec = httptest.NewRecorder()
		req = httptest.NewRequest(http.MethodPost, "/internal/conntrack", bytes.NewBufferString(`{"src":"10.0.0.1","dst":"10.0.0.2","proto":"tcp","srcPort":1234,"dstPort":80}`))
		conntrackHandler().ServeHTTP(rec, req)
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("conntrack delete status = %d", rec.Code)
		}
	})

	t.Run("ownership stub already started", func(t *testing.T) {
		ownership.start(context.Background())
		if got := ownership.currentInterfaces(); got != nil {
			t.Fatalf("ownership current interfaces = %#v", got)
		}
	})
}
