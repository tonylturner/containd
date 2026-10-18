// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

package engineapp

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	dpengine "github.com/tonylturner/containd/pkg/dp/engine"
)

func TestHealthBootIDStableAcrossRequestsAndHandlers(t *testing.T) {
	t.Parallel()
	dp, err := dpengine.New(dpengine.Config{})
	if err != nil {
		t.Fatal(err)
	}
	var first string
	for range 3 {
		rec := httptest.NewRecorder()
		healthHandler(dp)(rec, httptest.NewRequest(http.MethodGet, "/health", nil))
		var out map[string]json.RawMessage
		if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
			t.Fatal(err)
		}
		var bootID string
		if err := json.Unmarshal(out["bootId"], &bootID); err != nil {
			t.Fatal(err)
		}
		if bootID == "" {
			t.Fatal("empty engine bootId")
		}
		if first != "" && bootID != first {
			t.Fatalf("bootId changed in one process: %q -> %q", first, bootID)
		}
		first = bootID
	}
}
