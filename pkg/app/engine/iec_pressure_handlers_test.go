// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 containd Authors

package engineapp

import (
	"encoding/json"
	"net/http/httptest"
	"testing"

	"github.com/tonylturner/containd/pkg/dp/engine"
)

func TestIEC104PressureHandler(t *testing.T) {
	e, err := engine.New(engine.Config{})
	if err != nil {
		t.Fatal(err)
	}
	handler := iec104PressureHandler(e)
	w := httptest.NewRecorder()
	handler(w, httptest.NewRequest("GET", "/internal/diagnostics/iec104", nil))
	var p engine.IEC104Pressure
	if err := json.Unmarshal(w.Body.Bytes(), &p); err != nil {
		t.Fatal(err)
	}
	if w.Code != 200 || p.Limits.Sessions != 4096 || p.HeldPackets != 0 {
		t.Fatal(w.Code, p)
	}
	w = httptest.NewRecorder()
	handler(w, httptest.NewRequest("POST", "/internal/diagnostics/iec104", nil))
	if w.Code != 405 {
		t.Fatal(w.Code)
	}
}
