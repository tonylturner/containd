// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

package engineapp

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/tonylturner/containd/pkg/cp/services"
)

type fakeAVOperator struct {
	err      error
	uploaded string
	body     string
	deleted  string
}

func (f *fakeAVOperator) Status(context.Context) map[string]any {
	return map[string]any{"ready": true, "db_version": "ClamAV 1.5.2/1/x"}
}

func (f *fakeAVOperator) RunFreshclamNow() error { return f.err }

func (f *fakeAVOperator) ListDefinitions() (services.AVDefinitionList, error) {
	return services.AVDefinitionList{Path: "/data/clamav/custom", Files: []string{"a.ndb"}}, f.err
}

func (f *fakeAVOperator) UploadDefinition(_ context.Context, name string, r io.Reader) (services.AVDefinition, error) {
	if f.err != nil {
		return services.AVDefinition{}, f.err
	}
	data, _ := io.ReadAll(r)
	f.uploaded, f.body = name, string(data)
	return services.AVDefinition{Name: name, Size: int64(len(data)), Active: true}, nil
}

func (f *fakeAVOperator) DeleteDefinition(_ context.Context, name string) error {
	if f.err == nil {
		f.deleted = name
	}
	return f.err
}

func serveAV(av avOperator, method, target string, body io.Reader) *httptest.ResponseRecorder {
	mux := http.NewServeMux()
	registerAVHandlers(mux, av, nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest(method, target, body))
	return rec
}

func TestAVHandlersDelegateToManager(t *testing.T) {
	av := &fakeAVOperator{}
	rec := serveAV(av, http.MethodGet, "/internal/av/status", nil)
	var status map[string]any
	if rec.Code != http.StatusOK || json.Unmarshal(rec.Body.Bytes(), &status) != nil || status["ready"] != true {
		t.Fatalf("status = %d %s", rec.Code, rec.Body)
	}
	if rec := serveAV(av, http.MethodPost, "/internal/av/update", nil); rec.Code != http.StatusAccepted {
		t.Fatalf("update = %d %s", rec.Code, rec.Body)
	}
	if rec := serveAV(av, http.MethodGet, "/internal/av/defs", nil); rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"files":["a.ndb"]`) {
		t.Fatalf("list = %d %s", rec.Code, rec.Body)
	}
	if rec := serveAV(av, http.MethodPost, "/internal/av/defs?name=new.ndb", strings.NewReader("Sig:0:*:41")); rec.Code != http.StatusOK || av.uploaded != "new.ndb" || av.body != "Sig:0:*:41" {
		t.Fatalf("upload = %d %s (%q %q)", rec.Code, rec.Body, av.uploaded, av.body)
	}
	if rec := serveAV(av, http.MethodDelete, "/internal/av/defs?name=new.ndb", nil); rec.Code != http.StatusOK || av.deleted != "new.ndb" {
		t.Fatalf("delete = %d %s", rec.Code, rec.Body)
	}
	if rec := serveAV(av, http.MethodPut, "/internal/av/defs", nil); rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("PUT defs = %d", rec.Code)
	}
	if rec := serveAV(av, http.MethodGet, "/internal/av/update", nil); rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("GET update = %d", rec.Code)
	}
}

func TestAVHandlersMapErrors(t *testing.T) {
	for _, tc := range []struct {
		err  error
		code int
	}{
		{fmt.Errorf("%w: bad name", services.ErrAVInvalid), http.StatusBadRequest},
		{fmt.Errorf("%w: busy", services.ErrAVConflict), http.StatusConflict},
		{services.ErrAVStopped, http.StatusServiceUnavailable},
		{errors.New("disk full"), http.StatusInternalServerError},
	} {
		av := &fakeAVOperator{err: tc.err}
		for _, req := range []struct{ method, target string }{
			{http.MethodPost, "/internal/av/update"},
			{http.MethodGet, "/internal/av/defs"},
			{http.MethodPost, "/internal/av/defs?name=x.ndb"},
			{http.MethodDelete, "/internal/av/defs?name=x.ndb"},
		} {
			if rec := serveAV(av, req.method, req.target, strings.NewReader("x")); rec.Code != tc.code || !strings.Contains(rec.Body.String(), tc.err.Error()) {
				t.Fatalf("%s %s with %v = %d %s, want %d", req.method, req.target, tc.err, rec.Code, rec.Body, tc.code)
			}
		}
	}
}
