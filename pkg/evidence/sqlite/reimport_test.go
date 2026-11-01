// SPDX-License-Identifier: Apache-2.0
package sqlite

import (
	"context"
	"database/sql"
	"testing"
	"time"

	"github.com/tonylturner/containd/pkg/dp/learn"
	"github.com/tonylturner/containd/pkg/evidence"
)

func TestNormalizationUpgradeReimportsRetainedCapture(t *testing.T) {
	ctx := context.Background()
	s, now, _ := newStore(t, evidence.Budgets{})
	old := metadata()
	var err error
	old.CaptureSHA256, err = evidence.Digest("retained-capture")
	if err != nil {
		t.Fatal(err)
	}
	// Seed the pre-normalization identity, as written by an older release.
	old.ID, err = evidence.Digest([]string{evidence.SchemaVersion, old.CaptureSHA256, old.DecoderVersion, old.ProfileFingerprint, old.SnapshotFingerprint})
	if err != nil {
		t.Fatal(err)
	}
	if err := s.write(ctx, func(tx *sql.Tx) error {
		old, err = s.create(ctx, tx, old)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	p := parent(old, "old")
	p.Authority.RoleEvidence = "decoder_and_connection"
	if _, err := s.Ingest(ctx, evidence.IngestRequest{DatasetID: old.ID, Parents: []evidence.Observation{p}, Seal: true}); err != nil {
		t.Fatal(err)
	}
	input := old
	input.ID = ""
	current, err := s.CreateDataset(ctx, input)
	if err != nil || current.ID == old.ID || current.State != evidence.DatasetImporting || current.Records != 0 {
		t.Fatalf("obsolete normalization reused: %+v %v", current, err)
	}
	p = parent(current, "new")
	p.Authority.RoleEvidence = learn.PortDecoderAuthority
	if _, err := s.Ingest(ctx, evidence.IngestRequest{DatasetID: current.ID, Parents: []evidence.Observation{p}, Seal: true}); err != nil {
		t.Fatal(err)
	}
	*now = now.Add(time.Hour)
	again, err := s.CreateDataset(ctx, input)
	if err != nil || again.ID != current.ID || again.State != evidence.DatasetSealed || !again.ExpiresAt.Equal(current.ExpiresAt) {
		t.Fatalf("current normalization failed to deduplicate: %+v %v", again, err)
	}
	retained, err := s.GetDataset(ctx, old.ID)
	if err != nil || retained.Records != 1 {
		t.Fatalf("historical dataset unreadable: %+v %v", retained, err)
	}
	g := learn.Generator{Store: s, Certifier: &learn.CompilerCertifier{Store: s}}
	result, err := g.Generate(ctx, learn.GenerateRequest{DatasetID: old.ID})
	if err != nil || len(result.Suggestions) != 0 || result.Withheld[evidence.WithheldMissingAuthority] != 1 {
		t.Fatalf("historical dataset did not fail closed: %+v %v", result, err)
	}
}

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
