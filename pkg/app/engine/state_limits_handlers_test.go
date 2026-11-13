// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 containd Authors

package engineapp

import (
	"encoding/json"
	"net/http/httptest"
	"testing"

	"github.com/tonylturner/containd/pkg/dp/engine"
	"github.com/tonylturner/containd/pkg/dp/limits"
)

func TestStateLimitsHandler(t *testing.T) {
	e, err := engine.New(engine.Config{})
	if err != nil {
		t.Fatal(err)
	}
	handler := stateLimitsHandler(e)
	w := httptest.NewRecorder()
	handler(w, httptest.NewRequest("GET", "/internal/diagnostics/state-limits", nil))
	var p limits.Snapshot
	if err := json.Unmarshal(w.Body.Bytes(), &p); err != nil {
		t.Fatal(err)
	}
	if w.Code != 200 || p.Budget.Limit != limits.DefaultMaxInspectionBytes || len(p.Tables) != 12 {
		t.Fatal(w.Code, p)
	}
	w = httptest.NewRecorder()
	handler(w, httptest.NewRequest("POST", "/internal/diagnostics/state-limits", nil))
	if w.Code != 405 {
		t.Fatal(w.Code)
	}
}
