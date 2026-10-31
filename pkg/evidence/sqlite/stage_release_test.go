// SPDX-License-Identifier: Apache-2.0
package sqlite

import (
	"context"
	"testing"

	"github.com/tonylturner/containd/pkg/dp/learn"
	"github.com/tonylturner/containd/pkg/evidence"
)

func TestFailedStageReleasePermitsReviewAndNewRequest(t *testing.T) {
	ctx := context.Background()
	s, _, _ := newStore(t, evidence.Budgets{})
	d := create(t, s, "release")
	ingest(t, s, d, "one", true)
	v := certified(t, s, d)
	v, err := s.ReviewSuggestion(ctx, "admin", learn.ReviewRequest{Selection: learn.Selection{ID: v.ID, Revision: v.Revision}, Approve: true, CoordinateApproved: true})
	if err != nil {
		t.Fatal(err)
	}
	req := learn.ApplyRequest{RequestID: "failed", Selections: []learn.Selection{{ID: v.ID, Revision: v.Revision}}}
	if _, err := s.ResolveForStage(ctx, req); err != nil {
		t.Fatal(err)
	}
	for range 2 {
		if err := s.ReleaseStage(ctx, req); err != nil {
			t.Fatal(err)
		}
	}
	v, err = s.ReviewSuggestion(ctx, "admin", learn.ReviewRequest{Selection: req.Selections[0], Approve: true, CoordinateApproved: true})
	if err != nil {
		t.Fatal("failed reservation still blocks review", err)
	}
	req.RequestID = "recovered"
	req.Selections[0].Revision = v.Revision
	if _, err := s.ResolveForStage(ctx, req); err != nil {
		t.Fatal("failed reservation still blocks a new request", err)
	}
	if err := s.MarkStaged(ctx, req); err != nil {
		t.Fatal(err)
	}
	if err := s.ReleaseStage(ctx, req); err != nil {
		t.Fatal(err)
	}
	if _, err := s.ResolveForStage(ctx, req); err != nil {
		t.Fatal("release erased completed receipt", err)
	}
}
