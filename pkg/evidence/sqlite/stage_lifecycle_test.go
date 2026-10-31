// SPDX-License-Identifier: Apache-2.0
package sqlite

import (
	"context"
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
				req := learn.ApplyRequest{RequestID: "lifecycle", Selections: []learn.Selection{{ID: v.ID, Revision: v.Revision}}}
				frozen, err := s.ResolveForStage(ctx, req)
				if err != nil {
					t.Fatal(err)
				}
				switch event {
				case "delete":
					err = s.DeleteDataset(ctx, d.ID)
				case "expire":
					*now = now.Add(2 * evidence.Retention)
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
					*now = now.Add(2 * evidence.Retention)
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
