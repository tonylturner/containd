// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

package httpapi

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/tonylturner/containd/pkg/dp/signatures"
)

type signatureMockEngine struct {
	*mockEngine
	added []signatures.Signature
}

func (m *signatureMockEngine) ListSignatures(context.Context) ([]signatures.Signature, error) {
	return m.added, nil
}
func (m *signatureMockEngine) AddSignature(_ context.Context, sig signatures.Signature) error {
	m.added = append(m.added, sig)
	return nil
}
func (m *signatureMockEngine) RemoveSignature(context.Context, string) (bool, error) {
	return false, nil
}
func (m *signatureMockEngine) ListSignatureMatches(context.Context, int) ([]signatures.Match, error) {
	return nil, nil
}

func TestAddSignatureValidatesThreshold(t *testing.T) {
	eng := &signatureMockEngine{mockEngine: &mockEngine{}}
	s := NewServerWithEngine(&mockStore{}, nil, eng)
	post := func(body string) *httptest.ResponseRecorder {
		rec := httptest.NewRecorder()
		req := authedRequest(http.MethodPost, "/api/v1/signatures", bytes.NewBufferString(body))
		req.Header.Set("Content-Type", "application/json")
		s.ServeHTTP(rec, req)
		return rec
	}
	const cond = `"conditions":[{"field":"kind","op":"equals","value":"exception"}]`
	if rec := post(`{"id":"BAD",` + cond + `,"threshold":{"count":10,"window":60000000000}}`); rec.Code != http.StatusBadRequest ||
		!strings.Contains(rec.Body.String(), "windowSeconds") {
		t.Fatalf("nanosecond window = %d %s, want 400", rec.Code, rec.Body.String())
	}
	if rec := post(`{"id":"OK",` + cond + `,"threshold":{"count":10,"windowSeconds":60}}`); rec.Code != http.StatusOK {
		t.Fatalf("valid threshold = %d %s", rec.Code, rec.Body.String())
	}
	if len(eng.added) != 1 || eng.added[0].Threshold.WindowSeconds != 60 {
		t.Fatalf("added = %+v", eng.added)
	}
}
