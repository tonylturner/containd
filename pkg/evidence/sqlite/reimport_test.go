// SPDX-License-Identifier: Apache-2.0
package sqlite

import (
	"context"
	"testing"

	"github.com/tonylturner/containd/pkg/evidence"
)

func TestExplicitDeleteAllowsGappedCaptureReimport(t *testing.T) {
	ctx := context.Background()
	s, _, _ := newStore(t, evidence.Budgets{})
	ds := create(t, s, "failed-import")
	if _, err := s.Ingest(ctx, evidence.IngestRequest{DatasetID: ds.ID, Gaps: []string{"import_failed"}, Seal: true}); err != nil {
		t.Fatal(err)
	}
	if err := s.DeleteDataset(ctx, ds.ID); err != nil {
		t.Fatal(err)
	}
	retry, err := s.CreateDataset(ctx, ds)
	if err != nil || retry.State != evidence.DatasetImporting || retry.Records != 0 || len(retry.Gaps) != 0 {
		t.Fatalf("deleted failed capture poisoned retry: %+v %v", retry, err)
	}
}
