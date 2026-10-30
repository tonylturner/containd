// SPDX-License-Identifier: Apache-2.0

package sqlite

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/tonylturner/containd/pkg/cp/config"
	"github.com/tonylturner/containd/pkg/dp/learn"
	"github.com/tonylturner/containd/pkg/evidence"
)

func pointer[T any](v T) *T { return &v }

func metadata() evidence.Dataset {
	return evidence.Dataset{Source: evidence.SourcePCAP, DecoderVersion: "decoder-1", ProfileFingerprint: "profile-1", SnapshotFingerprint: "snapshot-1", CaptureSHA256: "capture-1"}
}

func newStore(t *testing.T, budgets evidence.Budgets) (*Store, *time.Time, string) {
	t.Helper()
	now := time.Date(2026, 10, 30, 12, 0, 0, 0, time.UTC)
	path := filepath.Join(t.TempDir(), "private", "evidence.db")
	s, err := Open(path, Options{Now: func() time.Time { return now }, Budgets: budgets, WatchMetadata: func() (evidence.Dataset, error) { return metadata(), nil }, CompatibleProof: fixtureVersions})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s, &now, path
}

func create(t *testing.T, s *Store, id string) evidence.Dataset {
	t.Helper()
	d := metadata()
	var err error
	d.CaptureSHA256, err = evidence.Digest("capture-" + id)
	if err != nil {
		t.Fatal(err)
	}
	d, err = s.CreateDataset(context.Background(), d)
	if err != nil {
		t.Fatal(err)
	}
	return d
}

func parent(d evidence.Dataset, id string) evidence.Observation {
	return evidence.Observation{
		SchemaVersion: evidence.SchemaVersion, DatasetID: d.ID, Source: d.Source, ConnectionID: "incarnation", ParentID: id,
		DecoderVersion: d.DecoderVersion, ProfileFingerprint: d.ProfileFingerprint, SnapshotFingerprint: d.SnapshotFingerprint,
		CapturedAt: d.CreatedAt.Add(-365 * 24 * time.Hour), ObjectCount: 1,
		Quality:   evidence.Quality{Complete: true, Decoded: true},
		Service:   evidence.ServiceKey{ClientIP: "192.0.2.1", ServerIP: "192.0.2.2", ServerPort: 502, Transport: "tcp", Direction: "request", Protocol: "modbus", Coordinates: evidence.CoordinatesWire},
		Authority: evidence.Authority{Correlation: "wire", RoleCertain: true, StandardPort: true},
		Modbus:    &evidence.Modbus{UnitID: pointer(uint8(0)), FunctionCode: pointer(uint8(3)), Spans: []evidence.Span{{First: 1, Last: 2, Role: "read"}}},
	}
}

func ingest(t *testing.T, s *Store, d evidence.Dataset, id string, seal bool) evidence.IngestResult {
	t.Helper()
	out, err := s.Ingest(context.Background(), evidence.IngestRequest{DatasetID: d.ID, Parents: []evidence.Observation{parent(d, id)}, Seal: seal})
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func TestAdmissionExpiryAndEviction(t *testing.T) {
	ctx := context.Background()
	s, now, path := newStore(t, evidence.Budgets{MaxRecords: 2})
	a := create(t, s, "a")
	ingest(t, s, a, "one", true)
	*now = now.Add(time.Second)
	b := create(t, s, "b")
	ingest(t, s, b, "two", true)
	*now = now.Add(time.Second)
	c := create(t, s, "c")
	if got := ingest(t, s, c, "three", true); got.Accepted != 1 {
		t.Fatalf("admission: %+v", got)
	}
	if _, err := s.GetDataset(ctx, a.ID); !errors.Is(err, learn.ErrExpired) {
		t.Fatalf("evicted dataset: %v", err)
	}
	counts, err := s.Counters(ctx)
	if err != nil || counts.Records != 2 || counts.EvictedRecords != 1 || counts.EvictedBytes == 0 {
		t.Fatalf("counters: %+v %v", counts, err)
	}
	*now = now.Add(evidence.Retention)
	if _, err := s.GetDataset(ctx, b.ID); !errors.Is(err, learn.ErrExpired) {
		t.Fatalf("expiry follows store clock: %v", err)
	}
	if err := s.Maintain(ctx); err != nil {
		t.Fatal(err)
	}
	counts, err = s.Counters(ctx)
	if err != nil || counts.Records != 0 || counts.ExpiredRecords != 2 {
		t.Fatalf("expiry counters: %+v %v", counts, err)
	}
	assertGauges(t, s)
	info, err := os.Stat(path)
	if err != nil || info.Mode().Perm() != 0600 {
		t.Fatalf("private file: %v %v", info, err)
	}
}

func TestRejectWholeParentAndBatch(t *testing.T) {
	ctx := context.Background()
	s, _, _ := newStore(t, evidence.Budgets{MaxRecords: 1})
	d := create(t, s, "active")
	ingest(t, s, d, "one", false)
	got := ingest(t, s, d, "two", true)
	if got.Rejected != 1 || got.Accepted != 0 {
		t.Fatalf("must reject whole parent: %+v", got)
	}
	sealed, err := s.GetDataset(ctx, d.ID)
	if err != nil || sealed.Records != 1 || len(sealed.Gaps) != 1 {
		t.Fatalf("visible gap: %+v %v", sealed, err)
	}
	if _, err := s.Ingest(ctx, evidence.IngestRequest{DatasetID: d.ID, Parents: make([]evidence.Observation, 129)}); !errors.Is(err, ErrBudget) {
		t.Fatalf("batch budget: %v", err)
	}
	if _, err := s.Ingest(ctx, evidence.IngestRequest{DatasetID: d.ID, Parents: []evidence.Observation{parent(d, "three")}}); !errors.Is(err, ErrConflict) {
		t.Fatalf("sealed immutability: %v", err)
	}
}

func TestRestartStopsWatchAndSealsImport(t *testing.T) {
	ctx := context.Background()
	s, now, path := newStore(t, evidence.Budgets{})
	w, err := s.StartWatch(ctx, evidence.StartWatchRequest{})
	if err != nil || w.Deadline.Sub(w.StartedAt) != time.Hour {
		t.Fatalf("start: %+v %v", w, err)
	}
	if _, err := s.StartWatch(ctx, evidence.StartWatchRequest{}); !errors.Is(err, ErrConflict) {
		t.Fatalf("second watch: %v", err)
	}
	d := create(t, s, "interrupted")
	ingest(t, s, d, "one", false)
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	restarted, err := Open(path, Options{Now: func() time.Time { return *now }, CompatibleProof: fixtureVersions})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = restarted.Close() }()
	got, err := restarted.GetWatch(ctx, w.ID)
	if err != nil || got.StopReason != "restart" || got.StoppedAt == nil {
		t.Fatalf("watch resumed: %+v %v", got, err)
	}
	gotData, err := restarted.GetDataset(ctx, d.ID)
	if err != nil || gotData.State != evidence.DatasetSealed || len(gotData.Gaps) != 1 || gotData.Records != 1 {
		t.Fatalf("interrupted import: %+v %v", gotData, err)
	}
}

func fixtureVersions(v learn.Versions) bool {
	return v.Schema == learn.SuggestionSchemaVersion && v.Observation == evidence.SchemaVersion && v.Generator == "g1" && v.Evaluator == "e1"
}

func TestWatchDeadlineAndStop(t *testing.T) {
	ctx := context.Background()
	s, now, _ := newStore(t, evidence.Budgets{})
	w, err := s.StartWatch(ctx, evidence.StartWatchRequest{DurationSeconds: 1})
	if err != nil {
		t.Fatal(err)
	}
	*now = now.Add(time.Second)
	if _, err := s.ActiveWatch(ctx); !errors.Is(err, ErrNotFound) {
		t.Fatalf("expired lease collects: %v", err)
	}
	if err := s.Maintain(ctx); err != nil {
		t.Fatal(err)
	}
	stopped, err := s.StopWatch(ctx, w.ID)
	if err != nil || stopped.StopReason != "deadline" {
		t.Fatalf("stop: %+v %v", stopped, err)
	}
}

func certified(t *testing.T, s *Store, d evidence.Dataset) learn.Suggestion {
	t.Helper()
	ctx := context.Background()
	parents, err := s.ListObservations(ctx, d.ID, evidence.PageRequest{})
	if err != nil {
		t.Fatal(err)
	}
	digest, err := evidence.EvidenceDigest(parents.Items)
	if err != nil {
		t.Fatal(err)
	}
	v, err := s.PutDraft(ctx, learn.Suggestion{DatasetID: d.ID, Content: learn.SuggestionContent{
		Versions:       learn.Versions{Schema: learn.SuggestionSchemaVersion, Observation: evidence.SchemaVersion, Generator: "g1", Evaluator: "e1", Decoder: d.DecoderVersion, Profile: d.ProfileFingerprint, Snapshot: d.SnapshotFingerprint},
		EvidenceDigest: digest, RequiresCoordinateReview: true,
		Rules: []config.Rule{{ID: "exact-" + d.ID, Action: config.ActionAllow, ICS: config.ICSPredicate{Protocol: "modbus", Mode: "monitor"}}},
	}})
	if err != nil {
		t.Fatal(err)
	}
	p := learn.Certification{ContentID: v.ID, EvidenceDigest: digest, Versions: v.Content.Versions, CertifiedAt: s.now(), Positive: learn.ReplayTotals{Total: 1, Passed: 1}, Negative: learn.ReplayTotals{Total: 1, Passed: 1}, ParentRefs: []evidence.EvidenceRef{{DatasetID: d.ID, ObservationID: parents.Items[0].ID}}}
	v, err = s.SaveCertification(ctx, learn.Selection{ID: v.ID, Revision: v.Revision}, p)
	if err != nil {
		t.Fatal(err)
	}
	return v
}

func TestReviewAtomicResolutionAndRetry(t *testing.T) {
	ctx := context.Background()
	s, _, _ := newStore(t, evidence.Budgets{})
	d := create(t, s, "a")
	ingest(t, s, d, "one", true)
	v := certified(t, s, d)
	req := learn.ApplyRequest{RequestID: "retry-key", Selections: []learn.Selection{{ID: v.ID, Revision: v.Revision}}}
	if _, err := s.ResolveForStage(ctx, req); !errors.Is(err, learn.ErrReviewRequired) {
		t.Fatalf("wire review required: %v", err)
	}
	v, err := s.ReviewSuggestion(ctx, "admin", learn.ReviewRequest{Selection: req.Selections[0], Approve: true, CoordinateApproved: true})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.ResolveForStage(ctx, req); !errors.Is(err, learn.ErrStale) {
		t.Fatalf("review increments revision: %v", err)
	}
	req.Selections[0].Revision = v.Revision
	bad := req
	bad.Selections = append(append([]learn.Selection{}, req.Selections...), learn.Selection{ID: "unknown", Revision: 1})
	if _, err := s.ResolveForStage(ctx, bad); !errors.Is(err, ErrNotFound) {
		t.Fatalf("partial resolve: %v", err)
	}
	if _, err := s.ResolveForStage(ctx, req); err != nil {
		t.Fatal(err)
	}
	secondRequest := req
	secondRequest.RequestID += "-different"
	if _, err := s.ResolveForStage(ctx, secondRequest); !errors.Is(err, learn.ErrStale) {
		t.Fatalf("a second request resolved a reserved selection: %v", err)
	}
	if _, err := s.ReviewSuggestion(ctx, "admin", learn.ReviewRequest{Selection: req.Selections[0], Approve: false}); !errors.Is(err, learn.ErrStale) {
		t.Fatalf("review changed the resolved revision: %v", err)
	}
	if err := s.MarkStaged(ctx, req); err != nil {
		t.Fatal(err)
	}
	if err := s.MarkStaged(ctx, req); err != nil {
		t.Fatalf("complete retry: %v", err)
	}
	if _, err := s.ResolveForStage(ctx, req); err != nil {
		t.Fatalf("resolve retry: %v", err)
	}
	conflict := req
	conflict.Selections = []learn.Selection{{ID: v.ID, Revision: v.Revision + 1}}
	if _, err := s.ResolveForStage(ctx, conflict); !errors.Is(err, learn.ErrStale) {
		t.Fatalf("key reused: %v", err)
	}
	assertGauges(t, s)
}

func TestWithheldCountsOnceAndDuplicateIdentity(t *testing.T) {
	ctx := context.Background()
	s, _, _ := newStore(t, evidence.Budgets{})
	d := create(t, s, "a")
	ingest(t, s, d, "one", false)
	if got := ingest(t, s, d, "one", true); got.Duplicates != 1 {
		t.Fatalf("identity duplicate: %+v", got)
	}
	parents, err := s.ListObservations(ctx, d.ID, evidence.PageRequest{})
	if err != nil {
		t.Fatal(err)
	}
	for range 2 {
		if err := s.CountWithheld(ctx, parents.Items[0].ID, "g1", evidence.WithheldIECValue); err != nil {
			t.Fatal(err)
		}
	}
	c, err := s.Counters(ctx)
	if err != nil || c.Withheld[evidence.WithheldIECValue] != 1 {
		t.Fatalf("counted again: %+v %v", c, err)
	}
	assertGauges(t, s)
}

func assertGauges(t *testing.T, s *Store) {
	t.Helper()
	ctx := context.Background()
	var records, bytes, datasets uint64
	err := s.db.QueryRowContext(ctx, `SELECT
(SELECT count(*) FROM parents),
(SELECT coalesce(sum(length(data)),0) FROM parents)+
(SELECT coalesce(sum(length(data)),0) FROM datasets)+
(SELECT coalesce(sum(length(data)),0) FROM watches)+
(SELECT coalesce(sum(length(data)),0) FROM suggestions)+
(SELECT coalesce(sum(length(request)+length(resolved)),0) FROM stage_requests)+
(SELECT coalesce(sum(length(request)+length(suggestion)),0) FROM stage_selections)+
(SELECT coalesce(sum(length(data)),0) FROM counters)+
(SELECT coalesce(sum(length(id)+16),0) FROM tombstones)+
(SELECT coalesce(sum(length(parent)+length(version)+length(reason)),0) FROM withheld),
(SELECT count(*) FROM datasets)`).Scan(&records, &bytes, &datasets)
	if err != nil {
		t.Fatal(err)
	}
	gotRecords, gotBytes, gotDatasets, err := gauges(ctx, s.db)
	if err != nil || gotRecords != records || gotBytes != bytes || gotDatasets != datasets {
		t.Fatalf("transactional gauges diverged: got %d/%d/%d, want %d/%d/%d: %v", gotRecords, gotBytes, gotDatasets, records, bytes, datasets, err)
	}
}

func TestOpenPreservesSharedDirectoryPermissions(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0755); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "evidence.db")
	s, err := Open(path, Options{CompatibleProof: fixtureVersions})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })
	info, err := os.Stat(dir)
	if err != nil || info.Mode().Perm() != 0755 {
		t.Fatalf("changed shared data permissions: %v %v", info, err)
	}
	if info, err := os.Stat(path); err != nil || info.Mode().Perm() != 0600 {
		t.Fatalf("evidence file permissions: %v %v", info, err)
	}
}

func TestSchemaAndPhysicalLimits(t *testing.T) {
	s, now, path := newStore(t, evidence.Budgets{})
	var pages, size, spill int64
	if err := s.db.QueryRow(`PRAGMA max_page_count`).Scan(&pages); err != nil {
		t.Fatal(err)
	}
	if err := s.db.QueryRow(`PRAGMA page_size`).Scan(&size); err != nil {
		t.Fatal(err)
	}
	if err := s.db.QueryRow(`PRAGMA cache_spill`).Scan(&spill); err != nil {
		t.Fatal(err)
	}
	if pages*size > 120<<20 || spill != 0 {
		t.Fatalf("unbounded physical headroom: pages=%d size=%d spill=%d", pages, size, spill)
	}
	var version int
	if err := s.db.QueryRow(`SELECT version FROM schema_meta`).Scan(&version); err != nil {
		t.Fatal(err)
	}
	if _, err := s.db.Exec(`UPDATE schema_meta SET version=?`, version+1); err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	if next, err := Open(path, Options{Now: func() time.Time { return *now }, CompatibleProof: fixtureVersions}); err == nil {
		_ = next.Close()
		t.Fatal("silently accepted an incompatible schema")
	}
}

func TestRestartPreservesOrInvalidatesProofWithoutRegeneration(t *testing.T) {
	for _, compatible := range []bool{true, false} {
		name := "compatible"
		if !compatible {
			name = "changed-evaluator"
		}
		t.Run(name, func(t *testing.T) {
			ctx := context.Background()
			s, now, path := newStore(t, evidence.Budgets{})
			d := create(t, s, "a")
			ingest(t, s, d, "one", true)
			v := certified(t, s, d)
			v, err := s.ReviewSuggestion(ctx, "admin", learn.ReviewRequest{Selection: learn.Selection{ID: v.ID, Revision: v.Revision}, Approve: true, CoordinateApproved: true})
			if err != nil {
				t.Fatal(err)
			}
			expiry := v.ExpiresAt
			if err := s.Close(); err != nil {
				t.Fatal(err)
			}
			next, err := Open(path, Options{Now: func() time.Time { return *now }, CompatibleProof: func(versions learn.Versions) bool {
				// A guaranteed mismatch is derived from the authority, not a
				// future literal that might later become the current version.
				expected := v.Content.Versions.Evaluator
				if !compatible {
					expected += "-different"
				}
				return versions.Evaluator == expected
			}})
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = next.Close() }()
			got, err := next.GetSuggestion(ctx, v.ID)
			if err != nil || got.ExpiresAt != expiry {
				t.Fatalf("restart changed lease: %+v %v", got, err)
			}
			if compatible {
				if got.Proof == nil || got.Review == nil || got.Revision != v.Revision {
					t.Fatalf("compatible proof/review lost: %+v", got)
				}
			} else if got.Proof != nil || got.Review != nil || got.Revision != v.Revision+1 || got.Status != learn.SuggestionExpired {
				t.Fatalf("incompatible proof remained usable or silently regenerated: %+v", got)
			}
		})
	}
}

func TestParentBudgetsAndFingerprints(t *testing.T) {
	for _, tc := range []struct {
		name    string
		limits  evidence.Budgets
		mutate  func(*evidence.Observation)
		wantErr error
	}{
		{"parent-bytes", evidence.Budgets{MaxParentBytes: 100}, func(*evidence.Observation) {}, nil},
		{"declared-children", evidence.Budgets{MaxParentObjects: 1}, func(p *evidence.Observation) { p.ObjectCount = 2 }, nil},
		{"actual-children", evidence.Budgets{MaxParentObjects: 1}, func(p *evidence.Observation) {
			p.Modbus.Spans = append(p.Modbus.Spans, evidence.Span{First: 4, Last: 5, Role: "read"})
		}, nil},
		{"compact-dnp3-children", evidence.Budgets{MaxParentObjects: 1}, func(p *evidence.Observation) {
			p.Service.Protocol, p.Modbus = "dnp3", nil
			p.DNP3 = &evidence.DNP3{Objects: []evidence.DNP3Object{{Count: pointer(uint32(2)), Spans: []evidence.Span{{First: 1, Last: 2, Role: "target"}}}}}
		}, nil},
		{"snapshot-mismatch", evidence.Budgets{}, func(p *evidence.Observation) { p.SnapshotFingerprint += "-different" }, ErrConflict},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			s, _, _ := newStore(t, tc.limits)
			d := create(t, s, "a")
			p := parent(d, "one")
			tc.mutate(&p)
			got, err := s.Ingest(ctx, evidence.IngestRequest{DatasetID: d.ID, Parents: []evidence.Observation{p}, Seal: true})
			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("unexpected admission error: %v", err)
			}
			if tc.wantErr == nil && (got.Accepted != 0 || got.Rejected != 1) {
				t.Fatalf("parent was truncated instead of rejected: %+v", got)
			}
		})
	}
}

func TestPaginationAndPrivateImport(t *testing.T) {
	ctx := context.Background()
	s, _, _ := newStore(t, evidence.Budgets{})
	a := create(t, s, "a")
	b := create(t, s, "b")
	if page, err := s.ListDatasets(ctx, evidence.PageRequest{}); err != nil || len(page.Items) != 0 {
		t.Fatalf("private imports became list-visible: %+v %v", page, err)
	}
	if _, err := s.ListObservations(ctx, a.ID, evidence.PageRequest{}); !errors.Is(err, ErrNotFound) {
		t.Fatalf("private import observations visible: %v", err)
	}
	ingest(t, s, a, "one", true)
	ingest(t, s, b, "two", true)
	if b.ID < a.ID {
		a, b = b, a
	}
	first, err := s.ListDatasets(ctx, evidence.PageRequest{Limit: 1})
	if err != nil || len(first.Items) != 1 || first.Items[0].ID != a.ID || first.NextCursor == "" {
		t.Fatalf("first page: %+v %v", first, err)
	}
	second, err := s.ListDatasets(ctx, evidence.PageRequest{Limit: 1, Cursor: first.NextCursor})
	if err != nil || len(second.Items) != 1 || second.Items[0].ID != b.ID || second.NextCursor != "" {
		t.Fatalf("second page: %+v %v", second, err)
	}
	if _, err := s.ListDatasets(ctx, evidence.PageRequest{Limit: 201}); !errors.Is(err, ErrConflict) {
		t.Fatalf("unbounded list admitted: %v", err)
	}
}

func TestDuplicateSourceDoesNotRenewExpiry(t *testing.T) {
	ctx := context.Background()
	s, now, _ := newStore(t, evidence.Budgets{})
	d := create(t, s, "a")
	ingest(t, s, d, "one", true)
	*now = now.Add(time.Hour)
	got := create(t, s, "a")
	if got.ExpiresAt != d.ExpiresAt {
		t.Fatal("duplicate capture renewed expiry")
	}
	v := certified(t, s, d)
	*now = d.ExpiresAt
	if _, err := s.ResolveForStage(ctx, learn.ApplyRequest{RequestID: "too-late", Selections: []learn.Selection{{ID: v.ID, Revision: v.Revision}}}); !errors.Is(err, learn.ErrExpired) {
		t.Fatalf("expired proof must be distinguishable from an unknown selection: %v", err)
	}
}

func TestUnattributedCaptureGapSurvivesSealing(t *testing.T) {
	ctx := context.Background()
	s, _, _ := newStore(t, evidence.Budgets{})
	d := create(t, s, "a")
	if _, err := s.GetDataset(ctx, d.ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("private import metadata exposed: %v", err)
	}
	if _, err := s.Ingest(ctx, evidence.IngestRequest{DatasetID: d.ID, Seal: true, Gaps: []string{"truncated_capture"}}); err != nil {
		t.Fatal(err)
	}
	got, err := s.GetDataset(ctx, d.ID)
	if err != nil || got.State != evidence.DatasetSealed || len(got.Gaps) != 1 || got.Gaps[0] != "truncated_capture" {
		t.Fatalf("lost capture gap: %+v %v", got, err)
	}
	assertGauges(t, s)
}

func TestEvictionInvalidatesProofAndStageReservation(t *testing.T) {
	ctx := context.Background()
	s, now, _ := newStore(t, evidence.Budgets{MaxRecords: 1})
	a := create(t, s, "a")
	ingest(t, s, a, "one", true)
	v := certified(t, s, a)
	v, err := s.ReviewSuggestion(ctx, "admin", learn.ReviewRequest{Selection: learn.Selection{ID: v.ID, Revision: v.Revision}, Approve: true, CoordinateApproved: true})
	if err != nil {
		t.Fatal(err)
	}
	req := learn.ApplyRequest{RequestID: "reserved", Selections: []learn.Selection{{ID: v.ID, Revision: v.Revision}}}
	if _, err := s.ResolveForStage(ctx, req); err != nil {
		t.Fatal(err)
	}
	*now = now.Add(time.Second)
	b := create(t, s, "b")
	ingest(t, s, b, "two", true)
	if _, err := s.GetSuggestion(ctx, v.ID); !errors.Is(err, learn.ErrExpired) {
		t.Fatalf("dependent proof survived eviction: %v", err)
	}
	if _, err := s.ResolveForStage(ctx, req); !errors.Is(err, learn.ErrExpired) {
		t.Fatalf("reservation restored evicted evidence: %v", err)
	}
	if err := s.MarkStaged(ctx, req); !errors.Is(err, learn.ErrExpired) {
		t.Fatalf("completed a reservation with evicted evidence: %v", err)
	}
	assertGauges(t, s)
}

func TestLiveAndImportShareImmutableIngestion(t *testing.T) {
	ctx := context.Background()
	s, _, _ := newStore(t, evidence.Budgets{})
	pcap := create(t, s, "capture")
	ingest(t, s, pcap, "one", true)
	w, err := s.StartWatch(ctx, evidence.StartWatchRequest{})
	if err != nil {
		t.Fatal(err)
	}
	live, err := s.GetDataset(ctx, w.DatasetID)
	if err != nil {
		t.Fatal(err)
	}
	ingest(t, s, live, "one", false)
	if _, err := s.StopWatch(ctx, w.ID); err != nil {
		t.Fatal(err)
	}
	a, err := s.ListObservations(ctx, pcap.ID, evidence.PageRequest{})
	if err != nil {
		t.Fatal(err)
	}
	b, err := s.ListObservations(ctx, live.ID, evidence.PageRequest{})
	if err != nil {
		t.Fatal(err)
	}
	if len(a.Items) != 1 || len(b.Items) != 1 || a.Items[0].ParentDigest != b.Items[0].ParentDigest || a.Items[0].ID == b.Items[0].ID {
		t.Fatal("equivalent wire parents lost source-independent semantics or distinct replay references")
	}
	if _, err := s.Ingest(ctx, evidence.IngestRequest{DatasetID: live.ID, Parents: []evidence.Observation{parent(live, "late")}}); !errors.Is(err, ErrConflict) {
		t.Fatalf("stopped watch accepted new evidence: %v", err)
	}
}
