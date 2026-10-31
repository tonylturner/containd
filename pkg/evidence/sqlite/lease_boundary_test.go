// SPDX-License-Identifier: Apache-2.0
package sqlite

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/tonylturner/containd/pkg/evidence"
)

func TestStartAtDeadlineCannotSealAnUndrainedLease(t *testing.T) {
	ctx := context.Background()
	s, now, _ := newStore(t, evidence.Budgets{})
	watch, err := s.StartWatch(ctx, evidence.StartWatchRequest{DurationSeconds: 1})
	if err != nil {
		t.Fatal(err)
	}
	ds, err := s.GetDataset(ctx, watch.DatasetID)
	if err != nil {
		t.Fatal(err)
	}
	*now = watch.Deadline.Add(time.Millisecond)
	if _, err := s.StartWatch(ctx, evidence.StartWatchRequest{}); !errors.Is(err, ErrConflict) {
		t.Fatalf("start sealed an undrained lease: %v", err)
	}
	result, err := s.Ingest(ctx, evidence.IngestRequest{DatasetID: ds.ID, Parents: []evidence.Observation{parent(ds, "pending")}, CollectedAt: watch.StartedAt.Add(time.Millisecond)})
	if err != nil || result.Accepted != 1 {
		t.Fatalf("pre-deadline parent could not drain: %+v %v", result, err)
	}
	if _, err := s.StopWatch(ctx, watch.ID); err != nil {
		t.Fatal(err)
	}
}
