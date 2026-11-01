// SPDX-License-Identifier: Apache-2.0
package httpapi

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"

	"github.com/tonylturner/containd/pkg/cp/config"
)

func TestReconcileDoesNotAcknowledgeConfigRevision(t *testing.T) {
	for _, path := range []string{"/interfaces/reconcile", "/routing/reconcile"} {
		for _, header := range []string{"missing", "stale", "malformed"} {
			t.Run(path+"/"+header, func(t *testing.T) {
				resetTestRateLimiters()
				store := stageStore(t)
				cfg, err := store.Load(context.Background())
				if err != nil {
					t.Fatal(err)
				}
				cfg.Routing.Gateways = []config.Gateway{{Name: "running-gateway", Address: "192.0.2.2"}}
				if err := store.Save(context.Background(), cfg); err != nil {
					t.Fatal(err)
				}
				running, err := store.ReadSnapshot(context.Background(), config.SnapshotRunning, true)
				if err != nil {
					t.Fatal(err)
				}
				engine := &mockEngine{}
				server := NewServerWithEngine(store, nil, engine)
				before := testBaseRevision(store, context.Background())
				// Derive a guaranteed stale precondition from the actual store.
				if err := testMutateCandidate(store, context.Background(), func(candidate *config.Config) error {
					candidate.Interfaces[0].Alias = "candidate-only"
					candidate.Routing.Gateways = append(candidate.Routing.Gateways,
						config.Gateway{Name: "candidate-only", Address: "192.0.2.1"})
					return nil
				}); err != nil {
					t.Fatal(err)
				}
				current := testBaseRevision(store, context.Background())
				if current == before {
					t.Fatal("candidate save did not advance revision")
				}
				request := jsonAuthedRequest(http.MethodPost, "/api/v1"+path, bytes.NewBufferString(`{"confirm":"REPLACE"}`))
				switch header {
				case "stale":
					request.Header.Set(ifRevisionHeader, string(before))
				case "malformed":
					request.Header.Set(ifRevisionHeader, "not-a-revision")
				}
				response := httptest.NewRecorder()
				response.Header().Set(revisionHeader, string(before))
				server.ServeHTTP(response, request)
				if response.Code != http.StatusOK {
					t.Fatalf("status=%d body=%s", response.Code, response.Body)
				}
				if got := response.Header().Get(revisionHeader); got != "" {
					t.Fatalf("operational response acknowledged revision %q", got)
				}
				assertConfigResponseHeader(t, response, "")
				if testBaseRevision(store, context.Background()) != current {
					t.Fatal("reconcile mutated configuration")
				}
				if path == "/interfaces/reconcile" && !reflect.DeepEqual(engine.lastIf, running.Running.Interfaces) {
					t.Fatal("reconcile did not apply running interfaces")
				}
				if path == "/routing/reconcile" && !reflect.DeepEqual(engine.lastRTR, running.Running.Routing) {
					t.Fatal("reconcile did not apply running routing")
				}
			})
		}
	}
}
