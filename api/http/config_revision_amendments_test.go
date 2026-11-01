// SPDX-License-Identifier: Apache-2.0
package httpapi

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/tonylturner/containd/pkg/cp/config"
)

func TestConfigRevisionPendingConfirmAndNoOpConfirm(t *testing.T) {
	store := stageStore(t)
	server := NewServer(store, nil)
	ctx := context.Background()
	readDiff := func() *httptest.ResponseRecorder {
		t.Helper()
		return casRequest(t, server, "GET", "/config/diff", nil, "")
	}
	rec := readDiff()
	var body map[string]json.RawMessage
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if string(body["pendingConfirm"]) != "null" {
		t.Fatal("absent pending must be explicit null")
	}
	base := rec.Header().Get(revisionHeader)
	confirm := casRequest(t, server, "POST", "/config/confirm", nil, base)
	if confirm.Code != 200 || confirm.Header().Get(revisionHeader) != base {
		t.Fatalf("no-op confirm changed revision: %d %s", confirm.Code, confirm.Body)
	}
	if err := testCommitConfirmed(store, ctx, time.Hour); err != nil {
		t.Fatal(err)
	}
	snapshot, err := store.ReadSnapshot(ctx, config.SnapshotPair, true)
	if err != nil {
		t.Fatal(err)
	}
	rec = readDiff()
	var diff struct {
		PendingConfirm *struct {
			Deadline string `json:"deadline"`
		} `json:"pendingConfirm"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &diff); err != nil {
		t.Fatal(err)
	}
	if diff.PendingConfirm == nil {
		t.Fatal("pending deadline missing")
	}
	deadline, err := time.Parse(time.RFC3339Nano, diff.PendingConfirm.Deadline)
	if err != nil || deadline.Location() != time.UTC || !deadline.Equal(snapshot.PendingConfirm.Deadline) || rec.Header().Get(revisionHeader) != string(snapshot.Revision) {
		t.Fatal("deadline is not coherent UTC state")
	}
	stale := casRequest(t, server, "POST", "/config/confirm", nil, base)
	if stale.Code != 412 {
		t.Fatal("stale confirm accepted pending commit")
	}
	confirm = casRequest(t, server, "POST", "/config/confirm", nil, string(snapshot.Revision))
	if confirm.Code != 200 || confirm.Header().Get(revisionHeader) == string(snapshot.Revision) {
		t.Fatalf("confirm did not allocate: %d %s", confirm.Code, confirm.Body)
	}
	again := casRequest(t, server, "POST", "/config/confirm", nil, confirm.Header().Get(revisionHeader))
	if again.Code != 200 || again.Header().Get(revisionHeader) != confirm.Header().Get(revisionHeader) {
		t.Fatal("repeated confirm invalidated drafts")
	}
	rec = readDiff()
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if string(body["pendingConfirm"]) != "null" {
		t.Fatal("confirmation retained pending")
	}
}

func TestConfigRevisionSensitiveMissingHeadersAreRateLimited(t *testing.T) {
	for _, path := range []string{"/system/factory-reset", "/config/import"} {
		t.Run(path, func(t *testing.T) {
			resetTestRateLimiters()
			defer resetTestRateLimiters()
			server := NewServer(stageStore(t), nil)
			for i := 0; i < 31; i++ {
				rec := casRequest(t, server, "POST", path, nil, "")
				want := 428
				if i == 30 {
					want = 429
				}
				if rec.Code != want {
					t.Fatalf("attempt %d: %d want %d", i, rec.Code, want)
				}
			}
		})
	}
}

func TestConfigRevisionHealthAndErrorsHaveNoHeader(t *testing.T) {
	store := stageStore(t)
	server := NewServer(store, nil)
	rec := casRequest(t, server, "GET", "/health", nil, "")
	if rec.Code != 200 || rec.Header().Get(revisionHeader) != "" {
		t.Fatal("health disclosed revision")
	}
	for _, detail := range []bool{false, true} {
		router := gin.New()
		router.GET("/", func(c *gin.Context) {
			if _, err := readCandidate(c, store); err != nil {
				t.Fatal(err)
			}
			if detail {
				apiErrorDetail(c, 503, "failure", "detail")
			} else {
				apiError(c, 500, "failure")
			}
		})
		rec := httptest.NewRecorder()
		router.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))
		if rec.Header().Get(revisionHeader) != "" {
			t.Fatal("error retained read revision")
		}
	}
}

func TestConfigRevisionPreviewIgnoresPrecondition(t *testing.T) {
	store := stageStore(t)
	server := NewServer(store, nil)
	base := testBaseRevision(store, context.Background())
	for _, header := range []string{"", "malformed", string(base)} {
		rec := casRequest(t, server, "POST", "/templates/ics/apply", map[string]any{"template": "modbus_read_only", "preview": true}, header)
		if rec.Code != 200 || rec.Header().Get(revisionHeader) != "" {
			t.Fatalf("preview required header: %d %s", rec.Code, rec.Body)
		}
	}
	if testBaseRevision(store, context.Background()) != base {
		t.Fatal("preview mutated")
	}
}
