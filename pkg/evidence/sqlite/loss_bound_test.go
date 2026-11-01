// SPDX-License-Identifier: Apache-2.0
package sqlite

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/tonylturner/containd/pkg/evidence"
)

func TestLossIngestBoundCollapsesConservatively(t *testing.T) {
	ctx := context.Background()
	s, _, _ := newStore(t, evidence.Budgets{})
	d := create(t, s, "bounded-loss")
	losses := make([]evidence.CollectionLoss, evidence.MaxLosses+1)
	for i := range losses {
		losses[i] = evidence.CollectionLoss{Code: "watch_collection_loss", ConnectionID: fmt.Sprint(i)}
	}
	if _, err := s.Ingest(ctx, evidence.IngestRequest{DatasetID: d.ID, Losses: losses}); !errors.Is(err, ErrBudget) {
		t.Fatalf("unbounded batch admitted: %v", err)
	}
	for _, batch := range [][]evidence.CollectionLoss{losses[:600], losses[600:], losses[:600]} {
		if _, err := s.Ingest(ctx, evidence.IngestRequest{DatasetID: d.ID, Losses: batch}); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := s.Ingest(ctx, evidence.IngestRequest{DatasetID: d.ID, Seal: true}); err != nil {
		t.Fatal(err)
	}
	d, err := s.GetDataset(ctx, d.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(d.Losses) != 1 || d.Losses[0].Code != "collection_loss" || !d.LossTouches("unrelated", time.Now(), time.Now()) {
		t.Fatal("loss cap narrowed authority", d)
	}
}
