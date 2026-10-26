// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

package engineapp

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/tonylturner/containd/pkg/common/trust"
	"github.com/tonylturner/containd/pkg/cp/services"
)

type fakeTrust struct {
	applied trust.Bundle
	err     error
}

func (f *fakeTrust) SetTrust(_ context.Context, b trust.Bundle) error {
	if f.err != nil {
		return f.err
	}
	f.applied = b
	return nil
}

func (f *fakeTrust) TrustRevision() string { return f.applied.Revision }

func TestTrustHandler(t *testing.T) {
	ft := &fakeTrust{}
	serve := func(method, body string) *httptest.ResponseRecorder {
		rec := httptest.NewRecorder()
		trustHandler(ft).ServeHTTP(rec, httptest.NewRequest(method, "/internal/trust", strings.NewReader(body)))
		return rec
	}
	if rec := serve(http.MethodPost, `{"pem":"","revision":"none"}`); rec.Code != http.StatusOK || ft.applied.Revision != "none" || !strings.Contains(rec.Body.String(), `"revision":"none"`) {
		t.Fatalf("POST = %d %s", rec.Code, rec.Body)
	}
	if rec := serve(http.MethodGet, ""); rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"revision":"none"`) {
		t.Fatalf("GET = %d %s", rec.Code, rec.Body)
	}
	if rec := serve(http.MethodPost, `{`); rec.Code != http.StatusBadRequest {
		t.Fatalf("bad JSON = %d", rec.Code)
	}
	if rec := serve(http.MethodPost, `{"pem":"`+strings.Repeat("A", maxTrustBody)+`"}`); rec.Code != http.StatusBadRequest {
		t.Fatalf("oversize = %d", rec.Code)
	}
	ft.err = fmt.Errorf("%w: revision mismatch", services.ErrAVInvalid)
	if rec := serve(http.MethodPost, `{"pem":"x","revision":"y"}`); rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "revision mismatch") {
		t.Fatalf("invalid bundle = %d %s", rec.Code, rec.Body)
	}
	if rec := serve(http.MethodDelete, ""); rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("DELETE = %d", rec.Code)
	}
}
