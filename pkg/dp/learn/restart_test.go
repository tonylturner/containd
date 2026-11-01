// SPDX-License-Identifier: Apache-2.0
package learn_test

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/tonylturner/containd/pkg/dp/dpi"
	"github.com/tonylturner/containd/pkg/dp/flow"
	"github.com/tonylturner/containd/pkg/dp/learn"
	"github.com/tonylturner/containd/pkg/evidence"
	"github.com/tonylturner/containd/pkg/evidence/sqlite"
)

func TestRestartGapExcludesOverlappingConnections(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "evidence.db")
	now := request().Timestamp.Add(time.Hour)
	options := sqlite.Options{Now: func() time.Time { return now }, CompatibleProof: learn.CompatibleVersions, WatchMetadata: func() (evidence.Dataset, error) { return metadata(), nil }}
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
	for _, connection := range []string{"lagged", "overlapping"} {
		state := requestState()
		state.Connection.Store(&flow.Connection{Key: connection})
		ev := request()
		if connection == "overlapping" {
			ev.Timestamp = now
		}
		parents, err := learn.Normalize(ds, state, []dpi.Event{ev}, &serial)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := s.Ingest(ctx, evidence.IngestRequest{DatasetID: ds.ID, Parents: parents}); err != nil {
			t.Fatal(err)
		}
	}
	now = now.Add(time.Minute)
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
	ds, err = s.GetDataset(ctx, ds.ID)
	if err != nil || len(ds.Losses) != 1 || !ds.Losses[0].Start.IsZero() || !ds.Losses[0].End.IsZero() {
		t.Fatalf("restart uncertainty not durable: %+v %v", ds, err)
	}
	g := learn.Generator{Store: s, Certifier: &learn.CompilerCertifier{Store: s}, CountWithheld: s.CountWithheld}
	result, err := g.Generate(ctx, learn.GenerateRequest{DatasetID: ds.ID})
	if err != nil || len(result.Suggestions) != 0 || result.Withheld[evidence.WithheldCollectionLoss] != 2 {
		t.Fatalf("restart failed to isolate overlapping connection: %+v %v", result, err)
	}
	page, err := s.ListObservations(ctx, ds.ID, evidence.PageRequest{})
	if err != nil {
		t.Fatal(err)
	}
	for _, o := range page.Items {
		rules, reasons := learn.GenerateRelation(o)
		if len(reasons) > 0 {
			t.Fatal(reasons)
		}
		content := learn.SuggestionContent{Versions: learn.Versions{Schema: learn.SuggestionSchemaVersion, Observation: evidence.SchemaVersion, Generator: learn.GeneratorVersion, Evaluator: learn.EvaluatorVersion, Decoder: ds.DecoderVersion, Profile: ds.ProfileFingerprint, Snapshot: ds.SnapshotFingerprint}, Rules: rules}
		content.EvidenceDigest, err = evidence.EvidenceDigest([]evidence.Observation{o})
		if err != nil {
			t.Fatal(err)
		}
		_, err = g.Certifier.Certify(ctx, content, []evidence.EvidenceRef{{DatasetID: ds.ID, ObservationID: o.ID}})
		if err == nil {
			t.Fatalf("direct certification of %s: %v", o.ConnectionID, err)
		}
	}
}
