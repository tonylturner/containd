// SPDX-License-Identifier: Apache-2.0

package learn_test

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/tonylturner/containd/pkg/dp/dpi"
	"github.com/tonylturner/containd/pkg/dp/flow"
	"github.com/tonylturner/containd/pkg/dp/learn"
	"github.com/tonylturner/containd/pkg/evidence"
	"github.com/tonylturner/containd/pkg/evidence/sqlite"
)

func TestCollectionLossExclusionsAndDirectCertification(t *testing.T) {
	for _, kind := range []string{"connection", "tuple", "host pair", "interval", "legacy", "counter-only", "budget"} {
		t.Run(kind, func(t *testing.T) {
			ctx := context.Background()
			path := filepath.Join(t.TempDir(), "evidence.db")
			options := sqlite.Options{CompatibleProof: learn.CompatibleVersions}
			if kind == "budget" {
				options.Budgets.MaxParentObjects = 1
			}
			store, err := sqlite.Open(path, options)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = store.Close() })
			ds, err := store.CreateDataset(ctx, metadata())
			if err != nil {
				t.Fatal(err)
			}
			var serial uint64
			var excluded evidence.Observation
			var affectedWire evidence.Tuple
			ingest := func(connection string, at time.Time, objects uint32) {
				t.Helper()
				state := requestState()
				if connection == "clean" {
					state.Key.SrcPort++
				}
				state.Connection.Store(&flow.Connection{Key: connection})
				ev := request()
				ev.Timestamp = at
				parents, err := learn.Normalize(ds, state, []dpi.Event{ev}, &serial)
				if err != nil {
					t.Fatal(err)
				}
				if connection == "affected" {
					affectedWire = parents[0].Authority.Wire
				}
				parents[0].ObjectCount = objects
				result, err := store.Ingest(ctx, evidence.IngestRequest{DatasetID: ds.ID, Parents: parents})
				if err != nil || (objects > 1 && result.Rejected != 1) || (objects == 1 && result.Accepted != 1) {
					t.Fatalf("ingest %+v: %v", result, err)
				}
			}
			at := request().Timestamp
			// Legacy timestamp-only loss cannot prove any incarnation disjoint.
			ingest("affected", at, 1)
			later := "affected"
			if kind == "tuple" || kind == "host pair" {
				later = "reused-tuple"
			}
			ingest(later, at.Add(2*time.Minute), 1)
			ingest("clean", at.Add(3*time.Minute), 1)
			req := evidence.IngestRequest{DatasetID: ds.ID, Seal: true}
			switch kind {
			case "connection":
				req.Losses = []evidence.CollectionLoss{{Code: "collection_drop", ConnectionID: "affected"}}
			case "tuple", "host pair":
				req.Losses = []evidence.CollectionLoss{{Code: "capture_truncated", Scope: evidence.LossScope{Source: affectedWire.Source, Destination: affectedWire.Destination, Transport: affectedWire.Transport, Ports: kind == "tuple"}}}
			case "interval":
				req.Losses = []evidence.CollectionLoss{{Code: "capture_stop", Start: at.Add(time.Minute), End: at.Add(time.Minute)}}
			case "legacy":
				req.Gaps = []string{"unlocalized_gap"}
			case "counter-only":
				req.LostBatches = 1
			case "budget":
				ingest("affected", at.Add(time.Minute), 2)
			}
			if _, err := store.Ingest(ctx, req); err != nil {
				t.Fatal(err)
			}
			if err := store.Close(); err != nil {
				t.Fatal(err)
			}
			store, err = sqlite.Open(path, options)
			if err != nil {
				t.Fatal(err)
			}
			page, err := store.ListObservations(ctx, ds.ID, evidence.PageRequest{})
			if err != nil {
				t.Fatal(err)
			}
			for _, o := range page.Items {
				if o.ConnectionID == "affected" {
					excluded = o
				}
			}
			g := learn.Generator{Store: store, Certifier: &learn.CompilerCertifier{Store: store}, CountWithheld: store.CountWithheld}
			wantSuggestions, wantWithheld := 1, uint64(2)
			if kind == "legacy" || kind == "counter-only" || kind == "interval" || kind == "host pair" {
				wantSuggestions, wantWithheld = 0, 3
			}
			for range 2 {
				result, err := g.Generate(ctx, learn.GenerateRequest{DatasetID: ds.ID})
				if err != nil || len(result.Suggestions) != wantSuggestions || result.Withheld[evidence.WithheldCollectionLoss] != wantWithheld {
					t.Fatalf("loss generation: %+v %v", result, err)
				}
				if wantSuggestions > 0 {
					suggestion, err := store.GetSuggestion(ctx, result.Suggestions[0].ID)
					if err != nil || suggestion.Proof == nil || len(suggestion.Proof.ParentRefs) != 1 {
						t.Fatalf("clean proof: %+v %v", suggestion, err)
					}
				}
			}
			counts, err := store.Counters(ctx)
			if err != nil || counts.Withheld[evidence.WithheldCollectionLoss] != wantWithheld {
				t.Fatalf("durable/idempotent loss counts: %+v %v", counts, err)
			}
			// Build a valid current-version content independently of generation.
			// Direct certification must scan the rest of the connection/dataset.
			bundle, reasons := learn.GenerateRelation(excluded)
			if len(reasons) != 0 {
				t.Fatalf("fixture is not otherwise eligible: %v", reasons)
			}
			digest, err := evidence.EvidenceDigest([]evidence.Observation{excluded})
			if err != nil {
				t.Fatal(err)
			}
			content := learn.SuggestionContent{
				Versions: learn.Versions{Schema: learn.SuggestionSchemaVersion, Observation: evidence.SchemaVersion,
					Generator: learn.GeneratorVersion, Evaluator: learn.EvaluatorVersion,
					Decoder: ds.DecoderVersion, Profile: ds.ProfileFingerprint, Snapshot: ds.SnapshotFingerprint},
				EvidenceDigest: digest, Rules: bundle,
			}
			if _, err := g.Certifier.Certify(ctx, content, []evidence.EvidenceRef{{DatasetID: ds.ID, ObservationID: excluded.ID}}); !errors.Is(err, learn.ErrNotCertified) {
				t.Fatalf("direct certification accepted loss-affected reference: %v", err)
			}
		})
	}
}
