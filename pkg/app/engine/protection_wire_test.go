// SPDX-License-Identifier: Apache-2.0

package engineapp

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestProtectionApplyAndHealthWireShape(t *testing.T) {
	dp := newCountingDP(t)
	c := testProtectionCoordinator(t, dp)
	w := coordinatedPost(applyRulesHandler(dp.Engine, nil, c), "wire-apply", `{}`)
	if w.Code != 200 {
		t.Fatalf("apply: %d %s", w.Code, w.Body)
	}
	assertShape := func(body []byte) {
		t.Helper()
		var st map[string]json.RawMessage
		if err := json.Unmarshal(body, &st); err != nil {
			t.Fatal(err)
		}
		for _, field := range []string{"bootId", "applyId", "installedApplyId", "state", "retryable", "observedAt", "components", "effects"} {
			if st[field] == nil {
				t.Fatalf("missing frozen field %s: %s", field, body)
			}
		}
		var boot, apply, state, at string
		json.Unmarshal(st["bootId"], &boot)
		json.Unmarshal(st["applyId"], &apply)
		json.Unmarshal(st["state"], &state)
		json.Unmarshal(st["observedAt"], &at)
		if boot != engineBootID || apply != "wire-apply" || state != "disabled" {
			t.Fatalf("identity/state: %s", body)
		}
		if _, err := time.Parse(time.RFC3339Nano, at); err != nil {
			t.Fatal(err)
		}
		if string(st["retryable"]) != "false" || string(st["effects"]) != "[]" {
			t.Fatalf("disabled observation: %s", body)
		}
		var components []map[string]json.RawMessage
		if err := json.Unmarshal(st["components"], &components); err != nil || len(components) == 0 {
			t.Fatalf("components: %s", body)
		}
		for _, component := range components {
			for _, field := range []string{"name", "required", "state", "reason", "since"} {
				if component[field] == nil {
					t.Fatalf("missing component field %s: %s", field, body)
				}
			}
		}
	}
	assertShape(w.Body.Bytes())
	w = httptest.NewRecorder()
	healthHandler(dp.Engine, nil).ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/health", nil))
	var health map[string]json.RawMessage
	if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &health) != nil {
		t.Fatalf("health: %d %s", w.Code, w.Body)
	}
	assertShape(health["protection"])
}
