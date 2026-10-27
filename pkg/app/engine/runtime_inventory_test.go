// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 containd Authors

package engineapp

import (
	"encoding/json"
	"net/http/httptest"
	"testing"

	"github.com/tonylturner/containd/pkg/dp/engine"
	"github.com/tonylturner/containd/pkg/dp/inventory"
)

func TestInventoryIEC104Section(t *testing.T) {
	e, err := engine.New(engine.Config{})
	if err != nil {
		t.Fatal(err)
	}
	w := httptest.NewRecorder()
	inventoryHandler(e)(w, httptest.NewRequest("GET", "/internal/inventory?section=iec104", nil))
	var s inventory.IEC104Snapshot
	if err := json.Unmarshal(w.Body.Bytes(), &s); err != nil {
		t.Fatal(err)
	}
	if w.Code != 200 || s.Pairs == nil || s.Limits.PointsPerCA != inventory.MaxIEC104Points {
		t.Fatal(w.Code, s)
	}
}

func TestInventoryUnavailableJSON(t *testing.T) {
	for _, tc := range []struct {
		path, method string
		item         bool
	}{
		{"/internal/inventory", "GET", false}, {"/internal/inventory?section=iec104", "GET", false},
		{"/internal/inventory", "DELETE", false}, {"/internal/inventory/192.0.2.1", "GET", true},
	} {
		w := httptest.NewRecorder()
		handler := inventoryHandler(nil)
		if tc.item {
			handler = inventoryItemHandler(nil)
		}
		handler(w, httptest.NewRequest(tc.method, tc.path, nil))
		if w.Code != 503 || w.Header().Get("Content-Type") != "application/json" || w.Body.String() != "{\"error\":\"inventory unavailable\"}\n" {
			t.Fatal(w.Code, w.Body.String())
		}
	}
}
