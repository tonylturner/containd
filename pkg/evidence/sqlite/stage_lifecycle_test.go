// SPDX-License-Identifier: Apache-2.0
package sqlite

import (
	"context"
	"errors"
	"reflect"
	"testing"
	"time"

	"github.com/tonylturner/containd/pkg/dp/learn"
	"github.com/tonylturner/containd/pkg/evidence"
)

func TestStageSnapshotSurvivesEvidenceLifecycle(t *testing.T) {
	for _, event := range []string{"delete", "expire", "evict"} {
		for _, release := range []bool{false, true} {
			name := event + "/complete"
			if release {
				name = event + "/release"
			}
			t.Run(name, func(t *testing.T) {
				ctx := context.Background()
				s, now, path := newStore(t, evidence.Budgets{MaxRecords: 1})
				d := create(t, s, "snapshot")
				ingest(t, s, d, "one", true)
				v := certified(t, s, d)
				v, err := s.ReviewSuggestion(ctx, "admin", learn.ReviewRequest{Selection: learn.Selection{ID: v.ID, Revision: v.Revision}, Approve: true, CoordinateApproved: true})
				if err != nil {
					t.Fatal(err)
				}
				// Resolve near evidence expiry to exercise the independent retry window.
				*now = d.ExpiresAt.Add(-time.Hour)
				req := learn.ApplyRequest{RequestID: "lifecycle", Selections: []learn.Selection{{ID: v.ID, Revision: v.Revision}}}
				frozen, err := s.ResolveForStage(ctx, req)
				if err != nil {
					t.Fatal(err)
				}
				switch event {
				case "delete":
					err = s.DeleteDataset(ctx, d.ID)
				case "expire":
					*now = d.ExpiresAt
					err = s.Maintain(ctx)
				case "evict":
					*now = now.Add(time.Second)
					other := create(t, s, "other")
					ingest(t, s, other, "two", true)
				}
				if err != nil {
					t.Fatal(err)
				}
				if _, err := s.GetSuggestion(ctx, v.ID); err == nil {
					t.Fatal("live evidence survived lifecycle event")
				}
				// Recovery after a process restart must not depend on the live rows.
				if err := s.Close(); err != nil {
					t.Fatal(err)
				}
				s, err = Open(path, Options{Now: func() time.Time { return *now }, CompatibleProof: fixtureVersions, Budgets: evidence.Budgets{MaxRecords: 1}})
				if err != nil {
					t.Fatal(err)
				}
				defer func() { _ = s.Close() }()
				for range 2 {
					got, err := s.ResolveForStage(ctx, req)
					if err != nil || !reflect.DeepEqual(got, frozen) {
						t.Fatalf("snapshot retry: %v %+v", err, got)
					}
					if release {
						break
					}
					if err := s.MarkStaged(ctx, req); err != nil {
						t.Fatal("complete", err)
					}
					*now = now.Add(time.Hour)
					if err := s.Maintain(ctx); err != nil {
						t.Fatal(err)
					}
				}
				for range 2 {
					if err := s.ReleaseStage(ctx, req); err != nil {
						t.Fatal("release", err)
					}
				}
				if !release {
					if _, err := s.ResolveForStage(ctx, req); err != nil {
						t.Fatal("release erased completed receipt", err)
					}
				}
				assertGauges(t, s)
			})
		}
	}
}

func TestExpiredStageRequestFreesAdmissionBudget(t *testing.T) {
	for _, complete := range []bool{false, true} {
		name := "pending"
		if complete {
			name = "completed"
		}
		t.Run(name, func(t *testing.T) {
			ctx := context.Background()
			s, now, _ := newStore(t, evidence.Budgets{})
			d := create(t, s, "receipt")
			ingest(t, s, d, "one", true)
			v := certified(t, s, d)
			v, err := s.ReviewSuggestion(ctx, "admin", learn.ReviewRequest{Selection: learn.Selection{ID: v.ID, Revision: v.Revision}, Approve: true, CoordinateApproved: true})
			if err != nil {
				t.Fatal(err)
			}
			*now = d.ExpiresAt.Add(-time.Hour)
			req := learn.ApplyRequest{RequestID: "expires", Selections: []learn.Selection{{ID: v.ID, Revision: v.Revision}}}
			frozen, err := s.ResolveForStage(ctx, req)
			if err != nil {
				t.Fatal(err)
			}
			expires := now.Add(evidence.Retention)
			var storedExpiry int64
			if err := s.db.QueryRowContext(ctx, `SELECT expires FROM stage_requests WHERE id=?`, req.RequestID).Scan(&storedExpiry); err != nil {
				t.Fatal(err)
			}
			if storedExpiry != expires.UnixNano() {
				t.Fatal("retry window did not start at resolve")
			}
			if complete {
				if err := s.MarkStaged(ctx, req); err != nil {
					t.Fatal(err)
				}
			}
			// Delete before evidence expiry, but after resolution so tombstones
			// outlive the receipt and do not affect measured budget reclamation.
			*now = now.Add(30 * time.Minute)
			if err := s.DeleteDataset(ctx, d.ID); err != nil {
				t.Fatal(err)
			}
			if err := s.Maintain(ctx); err != nil {
				t.Fatal(err)
			}
			before, err := s.Counters(ctx)
			if err != nil {
				t.Fatal(err)
			}
			var receiptBytes uint64
			if err := s.db.QueryRowContext(ctx, `SELECT length(request)+length(resolved) FROM stage_requests WHERE id=?`, req.RequestID).Scan(&receiptBytes); err != nil {
				t.Fatal(err)
			}
			// Reserve admission's metadata headroom, but not another dataset's
			// bytes until the receipt is freed. No dataset remains to evict.
			s.limits.MaxBytes = before.Bytes + 2048
			next := metadata()
			next.CaptureSHA256, err = evidence.Digest("next-capture")
			if err != nil {
				t.Fatal(err)
			}
			*now = expires.Add(-time.Nanosecond)
			got, err := s.ResolveForStage(ctx, req)
			if err != nil || !reflect.DeepEqual(got, frozen) {
				t.Fatalf("retry inside window: %v %+v", err, got)
			}
			if _, err := s.CreateDataset(ctx, next); !errors.Is(err, ErrBudget) {
				t.Fatalf("receipt did not consume admission budget: %v", err)
			}
			*now = expires
			if err := s.Maintain(ctx); err != nil {
				t.Fatal(err)
			}
			var requests, selections int
			if err := s.db.QueryRowContext(ctx, `SELECT (SELECT count(*) FROM stage_requests), (SELECT count(*) FROM stage_selections)`).Scan(&requests, &selections); err != nil {
				t.Fatal(err)
			}
			if requests != 0 || selections != 0 {
				t.Fatalf("expired reservation retained: %d requests, %d selections", requests, selections)
			}
			after, err := s.Counters(ctx)
			if err != nil || before.Bytes-after.Bytes != receiptBytes {
				t.Fatalf("receipt bytes not freed: before=%d after=%d receipt=%d err=%v", before.Bytes, after.Bytes, receiptBytes, err)
			}
			if err := s.MarkStaged(ctx, req); !errors.Is(err, ErrNotFound) {
				t.Fatalf("expired request still known: %v", err)
			}
			if _, err := s.CreateDataset(ctx, next); err != nil {
				t.Fatal("receipt expiry did not restore admission", err)
			}
			assertGauges(t, s)
		})
	}
}
