// SPDX-License-Identifier: Apache-2.0
package learn_test

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/tonylturner/containd/pkg/dp/dpi"
	"github.com/tonylturner/containd/pkg/dp/learn"
	"github.com/tonylturner/containd/pkg/evidence"
	"github.com/tonylturner/containd/pkg/evidence/sqlite"
)

func TestRestartGapDoesNotVoidCompleteParents(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "evidence.db")
	options := sqlite.Options{CompatibleProof: learn.CompatibleVersions, WatchMetadata: func() (evidence.Dataset, error) { return metadata(), nil }}
	s, err := sqlite.Open(path, options)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })
	watch, err := s.StartWatch(ctx, evidence.StartWatchRequest{})
	if err != nil {
		t.Fatal(err)
	}
	ds, err := s.GetDataset(ctx, watch.DatasetID)
	if err != nil {
		t.Fatal(err)
	}
	var serial uint64
	parents, err := learn.Normalize(ds, requestState(), []dpi.Event{request()}, &serial)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.Ingest(ctx, evidence.IngestRequest{DatasetID: ds.ID, Parents: parents}); err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	s, err = sqlite.Open(path, options)
	if err != nil {
		t.Fatal(err)
	}
	stopped, err := s.GetWatch(ctx, watch.ID)
	if err != nil || stopped.StopReason != "restart" {
		t.Fatal("restart did not stop the watch", err)
	}
	g := learn.Generator{Store: s, Certifier: &learn.CompilerCertifier{Store: s}}
	result, err := g.Generate(ctx, learn.GenerateRequest{DatasetID: ds.ID})
	if err != nil || len(result.Suggestions) != 1 {
		t.Fatalf("restart voided retained parents: %+v %v", result, err)
	}
	suggestion, err := s.GetSuggestion(ctx, result.Suggestions[0].ID)
	if err != nil || len(suggestion.Content.Limits) < 2 {
		t.Fatal("restart loss limit absent", err)
	}
}
