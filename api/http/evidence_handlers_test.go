// SPDX-License-Identifier: Apache-2.0

package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"reflect"
	"testing"
	"time"

	engineapi "github.com/tonylturner/containd/api/engine"
	"github.com/tonylturner/containd/pkg/cp/config"
	"github.com/tonylturner/containd/pkg/dp/learn"
	"github.com/tonylturner/containd/pkg/evidence"
)

type evidenceStageEngine struct {
	*stageEngine
	frozen         []learn.Suggestion
	resolveError   error
	completeError  error
	resolves, done int
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
	candidate, err := store.LoadCandidate(ctx)
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
	if err := store.MutateCandidate(ctx, func(cfg *config.Config) error {
		cfg.Firewall.Rules = append(cfg.Firewall.Rules, conflict, config.Rule{ID: "learned-legacy", Action: config.ActionAllow})
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	before, err := store.LoadCandidate(ctx)
	if err != nil {
		t.Fatal(err)
	}
	e := &evidenceStageEngine{stageEngine: &stageEngine{mockEngine: &mockEngine{}}, frozen: []learn.Suggestion{s}}
	rec := requestStage(t, NewServerWithEngine(store, nil, e), "POST", "/learn/apply", learn.ApplyRequest{RequestID: "conflict", Selections: []learn.Selection{{ID: s.ID, Revision: s.Revision}}})
	if rec.Code != 409 || e.done != 0 {
		t.Fatalf("conflict: %d %s", rec.Code, rec.Body)
	}
	assertConfigResponseHeader(t, rec, "")
	after, err := store.LoadCandidate(ctx)
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
