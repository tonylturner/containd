// SPDX-License-Identifier: Apache-2.0
package sqlite_test

import (
	"context"
	"net"
	"path/filepath"
	"testing"
	"time"

	"github.com/tonylturner/containd/pkg/dp/dpi"
	"github.com/tonylturner/containd/pkg/dp/flow"
	"github.com/tonylturner/containd/pkg/dp/learn"
	"github.com/tonylturner/containd/pkg/evidence"
	"github.com/tonylturner/containd/pkg/evidence/sqlite"
)

func check(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}
func meta() evidence.Dataset {
	return evidence.Dataset{Source: evidence.SourcePCAP, CaptureSHA256: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", DecoderVersion: "ics-1", ProfileFingerprint: "profile", SnapshotFingerprint: "snapshot"}
}
func TestOlderResolvedProofSurvivesUpgrade(t *testing.T) {
	for _, complete := range []bool{false, true} {
		t.Run(map[bool]string{false: "pending", true: "completed"}[complete], func(t *testing.T) {
			ctx := context.Background()
			path := filepath.Join(t.TempDir(), "upgrade.db")
			// Seed a historically valid proof from a generator that ignored gaps.
			oldVersion := learn.GeneratorVersion + "-historical"
			if oldVersion == learn.GeneratorVersion {
				t.Fatal("fixture version must differ")
			}
			s, e := sqlite.Open(path, sqlite.Options{CompatibleProof: func(v learn.Versions) bool { return v.Generator == oldVersion }})
			check(t, e)
			ds, e := s.CreateDataset(ctx, meta())
			check(t, e)
			state := &flow.State{Key: flow.Key{SrcIP: net.ParseIP("192.0.2.1"), DstIP: net.ParseIP("192.0.2.2"), SrcPort: 40000, DstPort: 502, Proto: 6}}
			ev := dpi.Event{Proto: "modbus", Kind: "request", Timestamp: time.Unix(100, 0), Attributes: map[string]any{"unit_id": uint8(1), "function_code": uint8(3), "address": uint16(4), "quantity": uint16(3), "is_write": false}}
			var serial uint64
			parents, e := learn.Normalize(ds, state, []dpi.Event{ev}, &serial)
			check(t, e)
			_, e = s.Ingest(ctx, evidence.IngestRequest{DatasetID: ds.ID, Parents: parents, Gaps: []string{"watch_collection_loss"}, Seal: true})
			check(t, e)
			page, e := s.ListObservations(ctx, ds.ID, evidence.PageRequest{})
			check(t, e)
			p := page.Items[0]
			bundle, reasons := learn.GenerateRelation(p)
			if len(reasons) > 0 {
				t.Fatal(reasons)
			}
			digest, e := evidence.EvidenceDigest([]evidence.Observation{p})
			check(t, e)
			content := learn.SuggestionContent{Versions: learn.Versions{Schema: learn.SuggestionSchemaVersion, Observation: evidence.SchemaVersion, Generator: oldVersion, Evaluator: learn.EvaluatorVersion, Decoder: ds.DecoderVersion, Profile: ds.ProfileFingerprint, Snapshot: ds.SnapshotFingerprint}, EvidenceDigest: digest, Rules: bundle, RequiresCoordinateReview: true}
			v, e := s.PutDraft(ctx, learn.Suggestion{DatasetID: ds.ID, Content: content})
			check(t, e)
			proof := learn.Certification{ContentID: v.ID, EvidenceDigest: digest, Versions: content.Versions, CertifiedAt: time.Now(), ParentRefs: []evidence.EvidenceRef{{DatasetID: ds.ID, ObservationID: p.ID}}, Positive: learn.ReplayTotals{Total: 1, Passed: 1}, Negative: learn.ReplayTotals{Total: 1, Passed: 1}}
			v, e = s.SaveCertification(ctx, learn.Selection{ID: v.ID, Revision: v.Revision}, proof)
			check(t, e)
			v, e = s.ReviewSuggestion(ctx, "admin", learn.ReviewRequest{Selection: learn.Selection{ID: v.ID, Revision: v.Revision}, Approve: true, CoordinateApproved: true})
			check(t, e)
			req := learn.ApplyRequest{RequestID: "crash-before-candidate-save", Selections: []learn.Selection{{ID: v.ID, Revision: v.Revision}}}
			_, e = s.ResolveForStage(ctx, req)
			check(t, e)
			if complete {
				check(t, s.MarkStaged(ctx, req))
			}
			check(t, s.Close())
			s, e = sqlite.Open(path, sqlite.Options{CompatibleProof: learn.CompatibleVersions})
			check(t, e)
			defer s.Close()
			expired, e := s.GetSuggestion(ctx, v.ID)
			check(t, e)
			t.Logf("live suggestion after upgrade: %s", expired.Status)
			frozen, e := s.ResolveForStage(ctx, req)
			check(t, e)
			t.Logf("retry returned %d suggestions; generator=%s, compatible=%v, binding=%v", len(frozen), frozen[0].Content.Versions.Generator, learn.CompatibleVersions(frozen[0].Proof.Versions), frozen[0].Proof.ValidateBinding(frozen[0].Content))
			if len(frozen) != 1 || !frozen[0].StageReconcileOnly {
				t.Fatal("incompatible snapshot can introduce candidate rules")
			}
			check(t, s.MarkStaged(ctx, req))
			check(t, s.MarkStaged(ctx, req))
			check(t, s.ReleaseStage(ctx, req))
			frozen, e = s.ResolveForStage(ctx, req)
			check(t, e)
			if !frozen[0].StageReconcileOnly {
				t.Fatal("completed receipt lost cutover restriction")
			}

		})
	}
}
