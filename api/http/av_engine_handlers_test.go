// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

package httpapi

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	engineclient "github.com/tonylturner/containd/api/engine"
	"github.com/tonylturner/containd/pkg/cp/config"
	cpservices "github.com/tonylturner/containd/pkg/cp/services"
)

func avRequest(t *testing.T, engine EngineClient, req *http.Request) *httptest.ResponseRecorder {
	t.Helper()
	resetTestRateLimiters()
	var s http.Handler
	if engine == nil {
		s = NewServerWithEngineAndServices(&mockStore{cfg: config.DefaultConfig()}, nil, nil, routeInventoryServices{}, newMockUserStore())
	} else {
		s = NewServerWithEngineAndServices(&mockStore{cfg: config.DefaultConfig()}, nil, engine, routeInventoryServices{}, newMockUserStore())
	}
	rec := httptest.NewRecorder()
	s.ServeHTTP(rec, req)
	return rec
}

func TestServicesStatusReportsEngineAV(t *testing.T) {
	rec := avRequest(t, &mockEngine{}, authedRequest(http.MethodGet, "/api/v1/services/status", nil))
	var out struct {
		AV     map[string]any            `json:"av"`
		Faults []cpservices.ServiceFault `json:"faults"`
	}
	if rec.Code != http.StatusOK || json.Unmarshal(rec.Body.Bytes(), &out) != nil {
		t.Fatalf("status = %d %s", rec.Code, rec.Body)
	}
	if out.AV["available"] != true || out.AV["ready"] != true {
		t.Fatalf("av status = %+v", out.AV)
	}

	out.AV = nil
	rec = avRequest(t, &mockEngine{avErr: errors.New("connection refused")}, authedRequest(http.MethodGet, "/api/v1/services/status", nil))
	if rec.Code != http.StatusOK || json.Unmarshal(rec.Body.Bytes(), &out) != nil {
		t.Fatalf("status = %d %s", rec.Code, rec.Body)
	}
	if out.AV["available"] != false || !strings.Contains(out.AV["error"].(string), "connection refused") || out.AV["enabled"] != nil {
		t.Fatalf("unreachable engine av status = %+v", out.AV)
	}
}

func TestAVOperationsDelegateToEngine(t *testing.T) {
	engine := &mockEngine{}
	if rec := avRequest(t, engine, authedRequest(http.MethodPost, "/api/v1/services/av/update", nil)); rec.Code != http.StatusAccepted || engine.avUpdates != 1 {
		t.Fatalf("update = %d %s (updates %d)", rec.Code, rec.Body, engine.avUpdates)
	}
	rec := avRequest(t, engine, authedRequest(http.MethodGet, "/api/v1/services/av/defs", nil))
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"files":["engine.ndb"]`) || !strings.Contains(rec.Body.String(), `"path":"/engine/defs"`) {
		t.Fatalf("list = %d %s", rec.Code, rec.Body)
	}
	upload := multipartProbeRequest(t, http.MethodPost, "/api/v1/services/av/defs", "file", "dir/custom.ndb", []byte("Sig:0:*:414243"))
	rec = avRequest(t, engine, upload)
	if rec.Code != http.StatusOK || engine.avUploadName != "custom.ndb" || string(engine.avUpload) != "Sig:0:*:414243" || !strings.Contains(rec.Body.String(), `"active":true`) {
		t.Fatalf("upload = %d %s (%q %q)", rec.Code, rec.Body, engine.avUploadName, engine.avUpload)
	}
	bad := multipartProbeRequest(t, http.MethodPost, "/api/v1/services/av/defs", "file", "notes.txt", []byte("x"))
	engine.avUploadName = ""
	if rec := avRequest(t, engine, bad); rec.Code != http.StatusBadRequest || engine.avUploadName != "" {
		t.Fatalf("invalid upload = %d %s", rec.Code, rec.Body)
	}
	if rec := avRequest(t, engine, authedRequest(http.MethodDelete, "/api/v1/services/av/defs?file=custom.ndb", nil)); rec.Code != http.StatusOK || engine.avDeleted != "custom.ndb" {
		t.Fatalf("delete = %d %s", rec.Code, rec.Body)
	}
}

func TestAVOperationsReportEngineFailures(t *testing.T) {
	requests := func(t *testing.T) []*http.Request {
		return []*http.Request{
			authedRequest(http.MethodPost, "/api/v1/services/av/update", nil),
			authedRequest(http.MethodGet, "/api/v1/services/av/defs", nil),
			multipartProbeRequest(t, http.MethodPost, "/api/v1/services/av/defs", "file", "x.ndb", []byte("Sig:0:*:41")),
			authedRequest(http.MethodDelete, "/api/v1/services/av/defs?file=x.ndb", nil),
		}
	}
	conflict := &engineclient.StatusError{Op: "av", Code: http.StatusConflict, Detail: "freshclam already running"}
	for _, tc := range []struct {
		name   string
		engine EngineClient
		code   int
		body   string
	}{
		{"engine request error passes through", &mockEngine{avErr: conflict}, http.StatusConflict, "freshclam already running"},
		{"engine server error is unavailable", &mockEngine{avErr: &engineclient.StatusError{Op: "av", Code: http.StatusInternalServerError, Detail: "disk"}}, http.StatusServiceUnavailable, "engine antivirus unavailable"},
		{"unreachable engine is unavailable", &mockEngine{avErr: errors.New("dial tcp: connection refused")}, http.StatusServiceUnavailable, "connection refused"},
		{"no engine is unavailable", nil, http.StatusServiceUnavailable, "engine unavailable"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			for _, req := range requests(t) {
				if rec := avRequest(t, tc.engine, req); rec.Code != tc.code || !strings.Contains(rec.Body.String(), tc.body) {
					t.Fatalf("%s %s = %d %s, want %d", req.Method, req.URL, rec.Code, rec.Body, tc.code)
				}
			}
		})
	}
}
