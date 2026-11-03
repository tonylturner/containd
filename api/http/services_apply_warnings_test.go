// SPDX-License-Identifier: Apache-2.0

package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"slices"
	"testing"
)

// Transport warnings are not delivery proof. Only typed owner failures
// become warning headers; missing observations never manufacture readiness.
func TestCommitCarriesEngineServiceWarnings(t *testing.T) {
	for _, tc := range []struct {
		name string
		err  error
		want []string
	}{
		{"applied", nil, nil},

		{"failed", errors.New("engine services status 503: AV service apply failed"),
			[]string{"av: owner delivery failed"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			store := stageStore(t)
			engine := &mockEngine{svcErr: tc.err}
			server := newTestServerWithEngine(store, &mockAuditStore{}, engine)
			rec := requestStage(t, server, http.MethodPost, "/config/commit", nil)
			if rec.Code != http.StatusOK || !engine.applied {
				t.Fatalf("status=%d applied=%v body=%s", rec.Code, engine.applied, rec.Body)
			}
			assertConfigResponseHeader(t, rec, "committed")
			var body struct{ Protection struct{ Ready bool } }
			if json.Unmarshal(rec.Body.Bytes(), &body) != nil || body.Protection.Ready {
				t.Fatal("transport success manufactured readiness")
			}
			if got := rec.Header().Values("X-Containd-Warnings"); !slices.Equal(got, tc.want) {
				t.Fatalf("X-Containd-Warnings = %q, want %q", got, tc.want)
			}
			replayed, err := replayTestConfig(context.Background(), store, engine, nil)
			if err != nil || !slices.Equal(replayed, tc.want) {
				t.Fatalf("replay warnings = %q err=%v, want %q", replayed, err, tc.want)
			}
		})
	}
}
