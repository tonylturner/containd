// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

package httpapi

import (
	"bytes"
	"errors"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func idsApplyRequest(t *testing.T, action string) *http.Request {
	t.Helper()
	if action != "import" {
		body := `[]`
		path := "/api/v1/ids/restore"
		if action == "set" {
			body = `{"enabled":true,"rules":[]}`
			path = "/api/v1/ids/rules"
		}
		req := authedRequest(http.MethodPost, path, strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		return req
	}
	var body bytes.Buffer
	writer := multipart.NewWriter(&body)
	file, err := writer.CreateFormFile("file", "test.rules")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := file.Write([]byte(`alert tcp any any -> any 2404 (msg:"test"; sid:1000001; rev:1;)`)); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	req := authedRequest(http.MethodPost, "/api/v1/ids/import", &body)
	req.Header.Set("Content-Type", writer.FormDataContentType())
	return req
}

func TestIDSHandlersDeferApplyResultsUntilCommit(t *testing.T) {
	for _, action := range []string{"set", "import", "restore"} {
		for _, result := range []struct {
			name    string
			err     error
			svcErr  error
			status  int
			warning string
		}{
			{name: "success", status: http.StatusOK},
			{name: "apply error", err: errors.New("engine unavailable"), status: http.StatusInternalServerError},
			{name: "infrastructure warning", svcErr: errors.New("services unavailable"), status: http.StatusOK, warning: "services: services unavailable"},
			{name: "ruleset permission failure", err: errors.New("operation not permitted"), status: http.StatusInternalServerError},
		} {
			t.Run(action+"/"+result.name, func(t *testing.T) {
				store := stageStore(t)
				engine := &mockEngine{err: result.err, svcErr: result.svcErr}
				audit := &mockAuditStore{}
				server := NewServerWithEngine(store, audit, engine)
				rec := httptest.NewRecorder()
				serveWithConfigRevision(t, server, rec, idsApplyRequest(t, action))
				if rec.Code != http.StatusOK || engine.applied {
					t.Fatalf("stage unexpectedly applied or failed: status=%d body=%s", rec.Code, rec.Body)
				}
				rec = requestStage(t, server, "POST", "/config/commit", nil)
				if rec.Code != result.status {
					t.Fatalf("status=%d want=%d body=%s", rec.Code, result.status, rec.Body)
				}
				wantConfigHeader := "committed"
				if result.status >= http.StatusBadRequest {
					wantConfigHeader = ""
				}
				assertConfigResponseHeader(t, rec, wantConfigHeader)
				if !engine.applied {
					t.Fatal("handler did not apply rules")
				}
				warnings := rec.Header().Values("X-Containd-Warnings")
				if result.warning == "" && len(warnings) != 0 || result.warning != "" && (len(warnings) != 1 || warnings[0] != result.warning) {
					t.Fatalf("warnings=%v want=%q", warnings, result.warning)
				}
				if result.status == http.StatusInternalServerError {
					if !strings.Contains(rec.Body.String(), `"error":"configuration apply failed"`) {
						t.Fatalf("apply error response=%s", rec.Body)
					}

				}
			})
		}
	}
}
