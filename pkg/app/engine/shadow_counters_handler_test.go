// SPDX-License-Identifier: Apache-2.0
package engineapp

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	dpengine "github.com/tonylturner/containd/pkg/dp/engine"
	"github.com/tonylturner/containd/pkg/dp/rules"
)

func TestInternalShadowCounters(t *testing.T) {
	dp, err := dpengine.New(dpengine.Config{})
	if err != nil {
		t.Fatal(err)
	}
	handler := shadowCountersHandler(dp)
	for _, applied := range []bool{false, true} {
		if applied {
			err := dp.ApplyRules(context.Background(), rules.Snapshot{Version: "installed", Firewall: []rules.Entry{{
				ID: "trial", Action: rules.ActionDeny, ICS: rules.ICSPredicate{Protocol: "modbus", Mode: "monitor"},
			}}})
			if err != nil {
				t.Fatal(err)
			}
		}
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/internal/firewall/shadow-counters", nil))
		var got dpengine.ShadowCounters
		if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil || rec.Code != http.StatusOK || got.Available != applied {
			t.Fatalf("status=%d body=%s err=%v", rec.Code, rec.Body, err)
		}
		if applied && (got.SnapshotVersion != "installed" || got.Since == nil || got.Unit != "messages" || len(got.Rules) != 1 || got.Rules[0].ShadowMatches != 0) {
			t.Fatalf("applied counters: %+v", got)
		}
	}
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/internal/firewall/shadow-counters", nil))
	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatal(rec.Code)
	}
}
