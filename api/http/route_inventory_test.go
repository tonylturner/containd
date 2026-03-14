// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

package httpapi

import (
	"bytes"
	"context"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"

	"github.com/tonylturner/containd/pkg/cp/config"
	"github.com/tonylturner/containd/pkg/cp/identity"
	dpevents "github.com/tonylturner/containd/pkg/dp/events"
)

type routeInventoryServices struct {
	customDefsPath string
}

func (s routeInventoryServices) Apply(ctx context.Context, cfg config.ServicesConfig) error {
	return nil
}

func (s routeInventoryServices) Status() any { return map[string]any{} }

func (s routeInventoryServices) RecentEvents(limit int) []dpevents.Event { return nil }

func (s routeInventoryServices) TriggerAVUpdate(ctx context.Context) error { return nil }

func (s routeInventoryServices) CustomDefsPath() string { return s.customDefsPath }

func newRouteInventoryServer(t *testing.T) *gin.Engine {
	t.Helper()
	resetTestRateLimiters()
	cfg := config.DefaultConfig()
	cfg.PCAP.Interfaces = []string{"wan"}
	customDefsPath := t.TempDir()
	cfg.Services.AV.ClamAV.CustomDefsPath = customDefsPath
	store := &mockStore{cfg: cfg}
	engine := newRuntimeMockEngine()
	userStore := newMockUserStore()
	resolver := identity.NewResolver()
	return NewServerWithEngineAndServices(
		store,
		nil,
		engine,
		routeInventoryServices{customDefsPath: customDefsPath},
		userStore,
		resolver,
	)
}

func sampleRoutePath(path string) string {
	replacer := strings.NewReplacer(
		":id", "sample",
		":name", "sample",
		":ip", "127.0.0.1",
	)
	return replacer.Replace(path)
}

func jsonAuthedRequest(method, path string, body *bytes.Buffer) *http.Request {
	req := authedRequest(method, path, body)
	req.Header.Set("Content-Type", "application/json")
	return req
}

func multipartProbeRequest(t *testing.T, method, path, fieldName, filename string, content []byte) *http.Request {
	t.Helper()

	var body bytes.Buffer
	writer := multipart.NewWriter(&body)
	part, err := writer.CreateFormFile(fieldName, filename)
	if err != nil {
		t.Fatalf("CreateFormFile: %v", err)
	}
	if _, err := part.Write(content); err != nil {
		t.Fatalf("Write content: %v", err)
	}
	if err := writer.Close(); err != nil {
		t.Fatalf("Close writer: %v", err)
	}

	req, _ := http.NewRequest(method, path, &body)
	req.Header.Set("Authorization", "Bearer "+testAdminToken)
	req.Header.Set("Content-Type", writer.FormDataContentType())
	return req
}

func routeProbeRequest(t *testing.T, method, path string) *http.Request {
	t.Helper()

	switch path {
	case "/api/v1/auth/login":
		return jsonAuthedRequest(method, path, loginBody("containd", testPassword))
	case "/api/v1/auth/login/mfa":
		return jsonAuthedRequest(
			method,
			path,
			bytes.NewBufferString(`{"challengeToken":"challenge","code":"000000"}`),
		)
	case "/api/v1/ids/import":
		return multipartProbeRequest(
			t,
			method,
			path,
			"file",
			"rules.txt",
			[]byte(`alert tcp any any -> any any (msg:"x"; sid:1;)`),
		)
	case "/api/v1/pcap/upload", "/api/v1/pcap/analyze":
		return multipartProbeRequest(
			t,
			method,
			path,
			"file",
			"sample.pcap",
			buildTestPCAP([][]byte{buildTestModbusEthernetFrame()}),
		)
	case "/api/v1/services/av/defs":
		return multipartProbeRequest(
			t,
			method,
			path,
			"file",
			"sample.ndb",
			[]byte("TestSig:0:*:414243"),
		)
	default:
		if method == http.MethodPost || method == http.MethodPatch || method == http.MethodPut {
			return jsonAuthedRequest(method, path, bytes.NewBufferString(`{}`))
		}
		return authedRequest(method, path, nil)
	}
}

func TestAPIEndpointInventorySanity(t *testing.T) {
	routes := newRouteInventoryServer(t).Routes()

	for _, route := range routes {
		route := route
		t.Run(route.Method+" "+route.Path, func(t *testing.T) {
			resetTestRateLimiters()
			s := newRouteInventoryServer(t)

			path := sampleRoutePath(route.Path)
			if path == "/api/v1/cli/complete" {
				path += "?line=" + url.QueryEscape("show interface ")
			}
			if path == "/api/v1/services/vpn/wireguard/status" {
				path += "?iface=wg0"
			}

			req := routeProbeRequest(t, route.Method, path)
			rec := httptest.NewRecorder()
			s.ServeHTTP(rec, req)

			if rec.Code >= 500 &&
				rec.Code != http.StatusNotImplemented &&
				rec.Code != http.StatusServiceUnavailable {
				t.Fatalf(
					"endpoint returned %d for %s %s body=%s",
					rec.Code,
					route.Method,
					path,
					rec.Body.String(),
				)
			}
		})
	}
}
