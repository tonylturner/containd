// SPDX-License-Identifier: Apache-2.0

package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	engineapi "github.com/tonylturner/containd/api/engine"
	"github.com/tonylturner/containd/pkg/cp/config"
	"github.com/tonylturner/containd/pkg/dp/learn"
	"github.com/tonylturner/containd/pkg/evidence"
	evidencesqlite "github.com/tonylturner/containd/pkg/evidence/sqlite"
)

type evidenceStageEngine struct {
	*stageEngine
	frozen         []learn.Suggestion
	resolveError   error
	completeError  error
	releaseError   error
	resolves, done int
	releases       int
}

func (e *evidenceStageEngine) Learn(_ context.Context, method, path, _ string, body json.RawMessage) (json.RawMessage, error) {
	if method != http.MethodPost {
		return nil, errors.New("unexpected read")
	}
	var req learn.ApplyRequest
	if err := json.Unmarshal(body, &req); err != nil {
		return nil, err
	}
	switch path {
	case "/learn/stage/resolve":
		e.resolves++
		if e.resolveError != nil {
			return nil, e.resolveError
		}
		return json.Marshal(e.frozen)
	case "/learn/stage/release":
		e.releases++
		return nil, e.releaseError
	case "/learn/stage/complete":
		e.done++
		return nil, e.completeError
	default:
		return nil, errors.New("unexpected engine operation")
	}
}

func stageProposal(t *testing.T) learn.Suggestion {
	t.Helper()
	u := uint8(0)
	content := learn.SuggestionContent{
		Versions:       learn.Versions{Schema: learn.SuggestionSchemaVersion, Observation: evidence.SchemaVersion, Generator: learn.GeneratorVersion, Evaluator: learn.EvaluatorVersion, Decoder: "ics-1", Profile: "profile", Snapshot: "snapshot"},
		EvidenceDigest: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		Rules: []config.Rule{{ID: "exact-content", Sources: []string{"192.0.2.1/32"}, Destinations: []string{"192.0.2.2/32"}, Protocols: []config.Protocol{{Name: "tcp", Port: "502"}}, Action: config.ActionAllow,
			ICS: config.ICSPredicate{Mode: "monitor", Protocol: "modbus", Direction: "request", FunctionCode: []uint8{3}, UnitID: &u, Addresses: []string{"4-5"}}}},
	}
	id, err := content.ContentID()
	if err != nil {
		t.Fatal(err)
	}
	proof := &learn.Certification{ContentID: id, EvidenceDigest: content.EvidenceDigest, Versions: content.Versions, CertifiedAt: time.Now(), ParentRefs: []evidence.EvidenceRef{{DatasetID: "ds", ObservationID: "parent"}}, Positive: learn.ReplayTotals{Total: 1, Passed: 1}, Negative: learn.ReplayTotals{Total: 12, Passed: 12}}
	return learn.Suggestion{ID: id, Revision: 2, DatasetID: "ds", Content: content, Proof: proof, Status: learn.SuggestionCertified}
}

func TestEvidenceStageAtomicRetry(t *testing.T) {
	store := stageStore(t)
	ctx := context.Background()
	running, err := store.Load(ctx)
	if err != nil {
		t.Fatal(err)
	}
	s := stageProposal(t)
	e := &evidenceStageEngine{stageEngine: &stageEngine{mockEngine: &mockEngine{}}, frozen: []learn.Suggestion{s}, completeError: errors.New("connection lost after candidate save")}
	server := NewServerWithEngine(store, nil, e)
	req := learn.ApplyRequest{RequestID: "retry-one", Selections: []learn.Selection{{ID: s.ID, Revision: s.Revision}}}
	first := requestStage(t, server, "POST", "/learn/apply", req)
	if first.Code != 503 {
		t.Fatalf("lost completion was hidden: %d %s", first.Code, first.Body)
	}
	assertConfigResponseHeader(t, first, "staged")
	e.completeError = nil
	for range 2 {
		rec := requestStage(t, server, "POST", "/learn/apply", req)
		if rec.Code != 200 {
			t.Fatalf("retry: %d %s", rec.Code, rec.Body)
		}
		assertConfigResponseHeader(t, rec, "staged")
	}
	candidateSnapshot1, err := store.ReadSnapshot(ctx, config.SnapshotCandidate, true)
	candidate := candidateSnapshot1.Candidate
	if err != nil {
		t.Fatal(err)
	}
	if len(candidate.Firewall.Rules) != len(running.Firewall.Rules)+1 || e.mutations != 0 || e.done != 3 {
		t.Fatalf("duplicate, activation or lost completion: %+v", candidate.Firewall.Rules)
	}
	after, err := store.Load(ctx)
	if err != nil || !reflect.DeepEqual(running, after) {
		t.Fatal("staging changed running config", err)
	}
}

func TestEvidenceStageConflictRollsBackWholeBatch(t *testing.T) {
	store := stageStore(t)
	ctx := context.Background()
	s := stageProposal(t)
	// The first new rule would be inserted before the conflict is encountered.
	old := s.Content.Rules[0]
	old.ID = "another-content"
	s.Content.Rules = append([]config.Rule{old}, s.Content.Rules...)
	id, err := s.Content.ContentID()
	if err != nil {
		t.Fatal(err)
	}
	s.ID, s.Proof.ContentID = id, id
	conflict := s.Content.Rules[1]
	conflict.ICS.Addresses = []string{"4-6"}
	if err := testMutateCandidate(store, ctx, func(cfg *config.Config) error {
		cfg.Firewall.Rules = append(cfg.Firewall.Rules, conflict, config.Rule{ID: "learned-legacy", Action: config.ActionAllow})
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	beforeSnapshot2, err := store.ReadSnapshot(ctx, config.SnapshotCandidate, true)
	before := beforeSnapshot2.Candidate
	if err != nil {
		t.Fatal(err)
	}
	e := &evidenceStageEngine{stageEngine: &stageEngine{mockEngine: &mockEngine{}}, frozen: []learn.Suggestion{s}}
	rec := requestStage(t, NewServerWithEngine(store, nil, e), "POST", "/learn/apply", learn.ApplyRequest{RequestID: "conflict", Selections: []learn.Selection{{ID: s.ID, Revision: s.Revision}}})
	if rec.Code != 409 || e.done != 0 || e.releases != 1 {
		t.Fatalf("conflict: %d %s", rec.Code, rec.Body)
	}
	assertConfigResponseHeader(t, rec, "")
	afterSnapshot3, err := store.ReadSnapshot(ctx, config.SnapshotCandidate, true)
	after := afterSnapshot3.Candidate
	if err != nil || !reflect.DeepEqual(before, after) {
		t.Fatal("partially staged conflict or deleted legacy", err)
	}
}

func TestEvidenceStageRejectsStaleAndInvalidSelections(t *testing.T) {
	for _, status := range []int{400, 404, 409, 410} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			store := stageStore(t)
			s := stageProposal(t)
			e := &evidenceStageEngine{stageEngine: &stageEngine{mockEngine: &mockEngine{}}, resolveError: &engineapi.EvidenceError{Status: status, Detail: "stale evidence"}}
			server := NewServerWithEngine(store, nil, e)
			rec := requestStage(t, server, "POST", "/learn/apply", learn.ApplyRequest{RequestID: "stale", Selections: []learn.Selection{{ID: s.ID, Revision: s.Revision}}})
			if rec.Code != status || e.done != 0 {
				t.Fatalf("status lost: %d %s", rec.Code, rec.Body)
			}
			assertConfigResponseHeader(t, rec, "")
		})
	}
	for _, selections := range [][]learn.Selection{nil, {{ID: "one"}}, {{ID: "one", Revision: 1}, {ID: "one", Revision: 2}}} {
		store := stageStore(t)
		e := &evidenceStageEngine{stageEngine: &stageEngine{mockEngine: &mockEngine{}}}
		rec := requestStage(t, NewServerWithEngine(store, nil, e), "POST", "/learn/apply", learn.ApplyRequest{RequestID: "invalid", Selections: selections})
		if rec.Code != 400 || e.resolves != 0 {
			t.Fatalf("invalid input resolved: %d %s", rec.Code, rec.Body)
		}
		assertConfigResponseHeader(t, rec, "")
	}
}

func TestEvidenceLegacyWarningsDoNotChangeContent(t *testing.T) {
	s := stageProposal(t)
	data, err := json.Marshal(s)
	if err != nil {
		t.Fatal(err)
	}
	enriched, err := addLegacyOverlapWarnings(data, []config.Rule{{ID: "learned-old", ICS: config.ICSPredicate{Protocol: "modbus"}}}, false)
	if err != nil {
		t.Fatal(err)
	}
	var result learn.Suggestion
	if err := json.Unmarshal(enriched, &result); err != nil {
		t.Fatal(err)
	}
	id, err := result.Content.ContentID()
	if err != nil || id != s.ID || len(result.LegacyOverlaps) != 1 {
		t.Fatal("warning changed content identity", err)
	}
}

// Completion and release failures are recovery failures, never input rejections.
func TestEvidenceStageRecoveryErrorsAreRetryable(t *testing.T) {
	for _, phase := range []string{"complete", "release"} {
		for _, status := range []int{400, 404, 409, 410, 503} {
			t.Run(phase+http.StatusText(status), func(t *testing.T) {
				store := stageStore(t)
				s := stageProposal(t)
				e := &evidenceStageEngine{stageEngine: &stageEngine{mockEngine: &mockEngine{}}, frozen: []learn.Suggestion{s}}
				failure := &engineapi.EvidenceError{Status: status, Detail: "evidence disappeared"}
				if phase == "complete" {
					e.completeError = failure
				} else {
					e.releaseError = failure
					conflict := s.Content.Rules[0]
					conflict.ICS.Addresses = []string{"4-6"}
					if err := testMutateCandidate(store, context.Background(), func(cfg *config.Config) error {
						cfg.Firewall.Rules = append(cfg.Firewall.Rules, conflict)
						return nil
					}); err != nil {
						t.Fatal(err)
					}
				}
				req := learn.ApplyRequest{RequestID: "recover-this-request", Selections: []learn.Selection{{ID: s.ID, Revision: s.Revision}}}
				server := NewServerWithEngine(store, nil, e)
				rec := requestStage(t, server, "POST", "/learn/apply", req)
				if rec.Code != 503 || !strings.Contains(rec.Body.String(), req.RequestID) {
					t.Fatalf("lost recovery identity: %d %s", rec.Code, rec.Body)
				}
				e.completeError, e.releaseError = nil, nil
				rec = requestStage(t, server, "POST", "/learn/apply", req)
				want := 200
				if phase == "release" {
					want = 409
				}
				if rec.Code != want {
					t.Fatalf("retry: %d %s", rec.Code, rec.Body)
				}
			})
		}
	}
}

type lifecycleStageEngine struct {
	*stageEngine
	evidence       *evidencesqlite.Store
	beforeFinish   func()
	loseCompletion bool
}

func (e *lifecycleStageEngine) Learn(ctx context.Context, _, path, _ string, body json.RawMessage) (json.RawMessage, error) {
	var req learn.ApplyRequest
	if err := json.Unmarshal(body, &req); err != nil {
		return nil, err
	}
	switch path {
	case "/learn/stage/resolve":
		values, err := e.evidence.ResolveForStage(ctx, req)
		if err != nil {
			return nil, err
		}
		return json.Marshal(values)
	case "/learn/stage/complete", "/learn/stage/release":
		if e.beforeFinish != nil {
			e.beforeFinish()
			e.beforeFinish = nil
		}
		if path == "/learn/stage/release" {
			return nil, e.evidence.ReleaseStage(ctx, req)
		}
		if e.loseCompletion {
			e.loseCompletion = false
			return nil, errors.New("connection lost before complete")
		}
		return nil, e.evidence.MarkStaged(ctx, req)
	default:
		return nil, errors.New("unexpected operation")
	}
}

func TestEvidenceStageLifecycleConverges(t *testing.T) {
	for _, event := range []string{"delete", "expire", "evict"} {
		for _, release := range []bool{false, true} {
			name := event + "/complete"
			if release {
				name = event + "/release"
			}
			t.Run(name, func(t *testing.T) {
				ctx := context.Background()
				now := time.Now().UTC()
				es, err := evidencesqlite.Open(filepath.Join(t.TempDir(), "evidence.db"), evidencesqlite.Options{
					Now: func() time.Time { return now }, Budgets: evidence.Budgets{MaxDatasets: 1}, CompatibleProof: func(learn.Versions) bool { return true },
				})
				if err != nil {
					t.Fatal(err)
				}
				defer func() { _ = es.Close() }()
				metadata := evidence.Dataset{Source: evidence.SourcePCAP, CaptureSHA256: "sha256:" + strings.Repeat("a", 64), DecoderVersion: "ics-1", ProfileFingerprint: "profile", SnapshotFingerprint: "snapshot"}
				d, err := es.CreateDataset(ctx, metadata)
				if err != nil {
					t.Fatal(err)
				}
				parent := evidence.Observation{SchemaVersion: evidence.SchemaVersion, DatasetID: d.ID, Source: d.Source, ConnectionID: "conn", ParentID: "one", CapturedAt: now,
					DecoderVersion: d.DecoderVersion, ProfileFingerprint: d.ProfileFingerprint, SnapshotFingerprint: d.SnapshotFingerprint, ObjectCount: 1,
					Quality: evidence.Quality{Complete: true, Decoded: true}, Service: evidence.ServiceKey{ClientIP: "192.0.2.1", ServerIP: "192.0.2.2", ServerPort: 502, Transport: "tcp", Protocol: "modbus", Direction: "request", Coordinates: evidence.CoordinatesWire},
					Authority: evidence.Authority{Correlation: "wire", RoleCertain: true, StandardPort: true}, Modbus: &evidence.Modbus{},
				}
				if _, err := es.Ingest(ctx, evidence.IngestRequest{DatasetID: d.ID, Parents: []evidence.Observation{parent}, Seal: true}); err != nil {
					t.Fatal(err)
				}
				parents, err := es.ListObservations(ctx, d.ID, evidence.PageRequest{})
				if err != nil {
					t.Fatal(err)
				}
				proposal := stageProposal(t)
				proposal.Content.EvidenceDigest, err = evidence.EvidenceDigest(parents.Items)
				if err != nil {
					t.Fatal(err)
				}
				draft, err := es.PutDraft(ctx, learn.Suggestion{DatasetID: d.ID, Content: proposal.Content})
				if err != nil {
					t.Fatal(err)
				}
				proof := *proposal.Proof
				proof.ContentID, proof.EvidenceDigest = draft.ID, draft.Content.EvidenceDigest
				proof.ParentRefs = []evidence.EvidenceRef{{DatasetID: d.ID, ObservationID: parents.Items[0].ID}}
				s, err := es.SaveCertification(ctx, learn.Selection{ID: draft.ID, Revision: draft.Revision}, proof)
				if err != nil {
					t.Fatal(err)
				}
				store := stageStore(t)
				beforeSnapshot4, err := store.ReadSnapshot(ctx, config.SnapshotCandidate, true)
				before := beforeSnapshot4.Candidate
				if err != nil {
					t.Fatal(err)
				}
				if release {
					conflict := s.Content.Rules[0]
					conflict.ICS.Addresses = []string{"4-6"}
					if err := testMutateCandidate(store, ctx, func(cfg *config.Config) error { cfg.Firewall.Rules = append(cfg.Firewall.Rules, conflict); return nil }); err != nil {
						t.Fatal(err)
					}
					beforeSnapshot5, err := store.ReadSnapshot(ctx, config.SnapshotCandidate, true)
					before = beforeSnapshot5.Candidate
					if err != nil {
						t.Fatal(err)
					}
				}
				now = d.ExpiresAt.Add(-time.Hour)
				e := &lifecycleStageEngine{stageEngine: &stageEngine{mockEngine: &mockEngine{}}, evidence: es, loseCompletion: true}
				e.beforeFinish = func() {
					switch event {
					case "delete":
						err = es.DeleteDataset(ctx, d.ID)
					case "expire":
						now = d.ExpiresAt
						err = es.Maintain(ctx)
					case "evict":
						now = now.Add(time.Second)
						metadata.CaptureSHA256 = "sha256:" + strings.Repeat("b", 64)
						_, err = es.CreateDataset(ctx, metadata)
					}
					if err != nil {
						t.Fatal(err)
					}
					if _, err := es.GetSuggestion(ctx, s.ID); err == nil {
						t.Fatal("live suggestion survived lifecycle event")
					}
				}
				server := NewServerWithEngine(store, nil, e)
				req := learn.ApplyRequest{RequestID: "lifecycle-retry", Selections: []learn.Selection{{ID: s.ID, Revision: s.Revision}}}
				rec := requestStage(t, server, "POST", "/learn/apply", req)
				if release {
					if rec.Code != 409 {
						t.Fatalf("release: %d %s", rec.Code, rec.Body)
					}
					if err := es.ReleaseStage(ctx, req); err != nil {
						t.Fatal("release retry", err)
					}
					afterSnapshot6, err := store.ReadSnapshot(ctx, config.SnapshotCandidate, true)
					after := afterSnapshot6.Candidate
					if err != nil || !reflect.DeepEqual(before, after) {
						t.Fatal("failed mutation changed candidate", err)
					}
					return
				}
				if rec.Code != 503 || !strings.Contains(rec.Body.String(), req.RequestID) {
					t.Fatalf("lost completion: %d %s", rec.Code, rec.Body)
				}
				for range 2 {
					rec = requestStage(t, server, "POST", "/learn/apply", req)
					if rec.Code != 200 {
						t.Fatalf("retry: %d %s", rec.Code, rec.Body)
					}
				}
				afterSnapshot7, err := store.ReadSnapshot(ctx, config.SnapshotCandidate, true)
				after := afterSnapshot7.Candidate
				if err != nil || len(after.Firewall.Rules) != len(before.Firewall.Rules)+1 {
					t.Fatal("duplicate or missing staged rules", err)
				}
			})
		}
	}
}

func TestEvidenceStageUpgradeOnlyReconcilesExistingRules(t *testing.T) {
	for _, existing := range []bool{false, true} {
		t.Run(map[bool]string{false: "not saved", true: "already saved"}[existing], func(t *testing.T) {
			ctx := context.Background()
			store := stageStore(t)
			s := stageProposal(t)
			// Rebind a genuine historical snapshot: binding remains valid, but the
			// generator is guaranteed different from the currently accepted authority.
			s.Content.Versions.Generator = learn.GeneratorVersion + "-historical"
			var err error
			s.ID, err = s.Content.ContentID()
			if err != nil {
				t.Fatal(err)
			}
			s.Proof.ContentID, s.Proof.Versions = s.ID, s.Content.Versions
			s.StageReconcileOnly = true
			if existing {
				if err := testMutateCandidate(store, ctx, func(cfg *config.Config) error {
					cfg.Firewall.Rules = append(cfg.Firewall.Rules, s.Content.Rules...)
					return nil
				}); err != nil {
					t.Fatal(err)
				}
			}
			before, err := store.ReadSnapshot(ctx, config.SnapshotCandidate, true)
			if err != nil {
				t.Fatal(err)
			}
			e := &evidenceStageEngine{stageEngine: &stageEngine{mockEngine: &mockEngine{}}, frozen: []learn.Suggestion{s}}
			server := NewServerWithEngine(store, nil, e)
			req := learn.ApplyRequest{RequestID: "upgraded-request", Selections: []learn.Selection{{ID: s.ID, Revision: s.Revision}}}
			for range 2 {
				rec := requestStage(t, server, "POST", "/learn/apply", req)
				if existing && rec.Code != 200 || !existing && rec.Code != 409 {
					t.Fatalf("upgrade status: %d %s", rec.Code, rec.Body)
				}
			}
			after, err := store.ReadSnapshot(ctx, config.SnapshotCandidate, true)
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(before.Candidate.Firewall.Rules, after.Candidate.Firewall.Rules) {
				t.Fatal("upgrade mutated candidate")
			}
			if e.releases != 0 {
				t.Fatal("lost historical receipt needed for reconciliation")
			}
		})
	}
}

func TestEvidenceStageUpgradeRevisionMismatch(t *testing.T) {
	ctx := context.Background()
	store := stageStore(t)
	s := stageProposal(t)
	s.StageReconcileOnly = true
	e := &evidenceStageEngine{stageEngine: &stageEngine{mockEngine: &mockEngine{}}, frozen: []learn.Suggestion{s}}
	server := NewServerWithEngine(store, nil, e)
	body, err := json.Marshal(learn.ApplyRequest{RequestID: "stale-upgrade", Selections: []learn.Selection{{ID: s.ID, Revision: s.Revision}}})
	if err != nil {
		t.Fatal(err)
	}
	req := withTestRevision(store, authedRequest(http.MethodPost, "/api/v1/learn/apply", strings.NewReader(string(body))))
	if err := testMutateCandidate(store, ctx, func(cfg *config.Config) error {
		cfg.System.Hostname = "external-edit"
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	before, err := store.ReadSnapshot(ctx, config.SnapshotCandidate, true)
	if err != nil {
		t.Fatal(err)
	}
	rec := httptest.NewRecorder()
	server.ServeHTTP(rec, req)
	if rec.Code != http.StatusPreconditionFailed {
		t.Fatalf("stale upgrade status: %d %s", rec.Code, rec.Body)
	}
	var failure struct {
		Code            string          `json:"code"`
		CurrentRevision config.Revision `json:"currentRevision"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &failure); err != nil {
		t.Fatal(err)
	}
	if failure.Code != "config_revision_mismatch" || failure.CurrentRevision != before.Revision {
		t.Fatalf("wrong revision failure: %+v", failure)
	}
	after, err := store.ReadSnapshot(ctx, config.SnapshotCandidate, true)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(before, after) || e.resolves != 1 || e.releases != 0 || e.done != 0 {
		t.Fatal("stale upgrade changed candidate or lost the historical receipt")
	}
	if rec.Header().Get(revisionHeader) != "" {
		t.Fatal("stale upgrade acknowledged a write")
	}
}
