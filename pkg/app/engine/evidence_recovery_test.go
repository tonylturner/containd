// SPDX-License-Identifier: Apache-2.0
package engineapp

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/tonylturner/containd/pkg/evidence"
)

func TestEvidenceCleanupRemainsAvailableAfterCollectorFailure(t *testing.T) {
	a := newEvidenceTestAPI(t)
	ctx := context.Background()
	watch, err := a.watch.start(ctx, evidence.StartWatchRequest{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := a.watch.stop(ctx, watch.ID); err != nil {
		t.Fatal(err)
	}
	a.watch.fail(errors.New("transient storage failure"))
	mux := http.NewServeMux()
	a.register(mux)
	for _, tc := range []struct{ method, path string }{{"GET", "/internal/learn/counters"}, {"DELETE", "/internal/learn/datasets/" + watch.DatasetID}} {
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, httptest.NewRequest(tc.method, tc.path, nil))
		if rec.Code >= 400 {
			t.Fatalf("cleanup unavailable after storage failure: %s %d %s", tc.method, rec.Code, rec.Body)
		}
	}
}
