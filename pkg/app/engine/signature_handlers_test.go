// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 containd Authors

package engineapp

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	engineapi "github.com/tonylturner/containd/api/engine"
	"github.com/tonylturner/containd/pkg/dp/dpi"
	"github.com/tonylturner/containd/pkg/dp/engine"
	"github.com/tonylturner/containd/pkg/dp/signatures"
)

func signatureMux(e *engine.Engine) *http.ServeMux {
	mux := http.NewServeMux()
	mux.HandleFunc("/internal/signatures", signaturesHandler(e))
	mux.HandleFunc("/internal/signatures/matches", signatureMatchesHandler(e))
	return mux
}

func customSignature(id string) signatures.Signature {
	return signatures.Signature{
		ID:         id,
		Name:       "Lab probe",
		Severity:   "high",
		Protocol:   "labproto",
		Conditions: []signatures.Condition{{Field: "kind", Op: "equals", Value: "probe"}},
	}
}

func TestSignaturesRoundTripThroughEngineClient(t *testing.T) {
	e, err := engine.New(engine.Config{})
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(signatureMux(e))
	defer srv.Close()
	client := engineapi.NewHTTPClient(srv.URL)
	ctx := context.Background()

	builtins, err := client.ListSignatures(ctx)
	if err != nil || len(builtins) == 0 || len(builtins) != len(e.SignatureEngine().List()) {
		t.Fatalf("ListSignatures = %d signatures, %v; want the engine's builtins", len(builtins), err)
	}
	matches, err := client.ListSignatureMatches(ctx, 5)
	if err != nil || matches == nil || len(matches) != 0 {
		t.Fatalf("empty matches = %#v, %v; want non-nil empty slice", matches, err)
	}

	if err := client.AddSignature(ctx, customSignature("CUSTOM-1")); err != nil {
		t.Fatal(err)
	}
	if err := client.AddSignature(ctx, customSignature("CUSTOM-1")); !errors.Is(err, engineapi.ErrSignatureExists) {
		t.Fatalf("duplicate AddSignature error = %v, want ErrSignatureExists", err)
	}
	if err := client.AddSignature(ctx, signatures.Signature{ID: "EMPTY"}); err == nil || !strings.Contains(err.Error(), "engine signature add status 400") {
		t.Fatalf("invalid AddSignature error = %v, want 400", err)
	}
	after, err := client.ListSignatures(ctx)
	if err != nil || len(after) != len(builtins)+1 || after[len(after)-1].ID != "CUSTOM-1" {
		t.Fatalf("ListSignatures after add = %d, %v", len(after), err)
	}

	for i := 0; i < 2; i++ {
		e.SignatureEngine().Match(dpi.Event{Proto: "labproto", Kind: "probe", FlowID: "flow-1"})
	}
	matches, err = client.ListSignatureMatches(ctx, 1)
	if err != nil || len(matches) != 1 || matches[0].Signature.ID != "CUSTOM-1" || matches[0].Event.FlowID != "flow-1" {
		t.Fatalf("ListSignatureMatches(1) = %#v, %v", matches, err)
	}

	removed, err := client.RemoveSignature(ctx, "CUSTOM-1")
	if err != nil || !removed {
		t.Fatalf("RemoveSignature = %v, %v; want true", removed, err)
	}
	removed, err = client.RemoveSignature(ctx, "CUSTOM-1")
	if err != nil || removed {
		t.Fatalf("second RemoveSignature = %v, %v; want false", removed, err)
	}
}

func TestSignatureAddsWithOneIDLoadOnce(t *testing.T) {
	e, err := engine.New(engine.Config{})
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(signatureMux(e))
	defer srv.Close()
	client := engineapi.NewHTTPClient(srv.URL)
	const adders = 8
	errs := make([]error, adders)
	var wg sync.WaitGroup
	for i := range adders {
		wg.Add(1)
		go func() {
			defer wg.Done()
			errs[i] = client.AddSignature(context.Background(), customSignature("RACE-1"))
		}()
	}
	wg.Wait()
	added := 0
	for _, err := range errs {
		switch {
		case err == nil:
			added++
		case !errors.Is(err, engineapi.ErrSignatureExists):
			t.Fatalf("AddSignature error = %v", err)
		}
	}
	loaded := 0
	for _, s := range e.SignatureEngine().List() {
		if s.ID == "RACE-1" {
			loaded++
		}
	}
	if added != 1 || loaded != 1 {
		t.Fatalf("%d adds succeeded and %d signatures loaded; want 1 and 1", added, loaded)
	}
}

func TestSignatureHandlersRejectBadRequestsAndMissingEngine(t *testing.T) {
	e, err := engine.New(engine.Config{})
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		method, path, body string
		want               int
	}{
		{http.MethodPut, "/internal/signatures", "", http.StatusMethodNotAllowed},
		{http.MethodPost, "/internal/signatures/matches", "", http.StatusMethodNotAllowed},
		{http.MethodPost, "/internal/signatures", "{", http.StatusBadRequest},
		{http.MethodDelete, "/internal/signatures", "", http.StatusBadRequest},
		{http.MethodPost, "/internal/signatures", `{"id":"BIG","conditions":[{"field":"kind","op":"equals","value":"x"}],"name":"` + strings.Repeat("x", maxSignatureBody) + `"}`, http.StatusBadRequest},
	} {
		w := httptest.NewRecorder()
		signatureMux(e).ServeHTTP(w, httptest.NewRequest(tc.method, tc.path, strings.NewReader(tc.body)))
		if w.Code != tc.want {
			t.Fatalf("%s %s = %d %q, want %d", tc.method, tc.path, w.Code, w.Body.String(), tc.want)
		}
	}
	for _, tc := range []struct{ method, path string }{
		{http.MethodGet, "/internal/signatures"},
		{http.MethodPost, "/internal/signatures"},
		{http.MethodDelete, "/internal/signatures?id=x"},
		{http.MethodGet, "/internal/signatures/matches"},
	} {
		w := httptest.NewRecorder()
		signatureMux(nil).ServeHTTP(w, httptest.NewRequest(tc.method, tc.path, nil))
		if w.Code != http.StatusServiceUnavailable || w.Header().Get("Content-Type") != "application/json" || w.Body.String() != "{\"error\":\"signature engine unavailable\"}\n" {
			t.Fatalf("%s %s without engine: %d %q", tc.method, tc.path, w.Code, w.Body.String())
		}
	}
}
