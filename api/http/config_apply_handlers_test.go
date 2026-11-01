// SPDX-License-Identifier: Apache-2.0
package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"
	"time"

	"github.com/tonylturner/containd/pkg/cp/config"
	dpengine "github.com/tonylturner/containd/pkg/dp/engine"
	"github.com/tonylturner/containd/pkg/dp/rules"
)

type transactionalEngine struct {
	*mockEngine
	attempts     []rules.Snapshot
	failRestore  bool
	configureErr error
}

func (e *transactionalEngine) ApplyRules(_ context.Context, snap rules.Snapshot) error {
	e.attempts = append(e.attempts, snap)
	if len(e.attempts) == 1 || e.failRestore {
		e.ruleset = dpengine.RulesetStatus{Error: "nft apply failed: operation not permitted"}
		return errors.New(e.ruleset.Error)
	}
	e.ruleset = dpengine.RulesetStatus{Ruleset: "restored rules", AppliedAt: time.Now()}
	return nil
}
func (e *transactionalEngine) Configure(ctx context.Context, cfg config.DataPlaneConfig) error {
	if e.configureErr != nil {
		return e.configureErr
	}
	return e.mockEngine.Configure(ctx, cfg)
}

func TestRunningChangesRestoreDocumentBankAndCandidate(t *testing.T) {
	for _, action := range []string{"commit", "commit_confirmed", "rollback"} {
		for _, failRestore := range []bool{false, true} {
			t.Run(action+"/restore="+map[bool]string{true: "failed", false: "ok"}[failRestore], func(t *testing.T) {
				ctx := context.Background()
				store := stageStore(t)
				if err := testCommit(store, ctx); err != nil {
					t.Fatal(err)
				} // establish rollback baseline
				running, err := store.Load(ctx)
				if err != nil {
					t.Fatal(err)
				}
				running.System.Hostname = "pre-request"
				running.DataPlane.Enforcement = true
				running.Firewall.DefaultAction = config.ActionAllow
				running.IDS.Rules = config.DefaultIDSConfig().Rules[1:2]
				if err := store.Save(ctx, running); err != nil {
					t.Fatal(err)
				}
				candidate, err := store.Load(ctx)
				if err != nil {
					t.Fatal(err)
				}
				candidate.System.Hostname = "failed-candidate"
				candidate.IDS.Rules = []config.IDSRule{}
				if err := testSaveCandidate(store, ctx, candidate); err != nil {
					t.Fatal(err)
				}
				candidateSnapshot1, _ := store.ReadSnapshot(ctx, config.SnapshotCandidate, true)
				candidate = candidateSnapshot1.Candidate
				engine := &transactionalEngine{mockEngine: &mockEngine{}, failRestore: failRestore}
				server := NewServerWithEngine(store, nil, engine)
				rec := requestStage(t, server, "POST", "/config/"+action, map[string]int{"ttl_seconds": 1})
				var body struct {
					Error        string `json:"error"`
					Detail       string `json:"detail"`
					Restored     bool   `json:"restored"`
					Reapplied    bool   `json:"reapplied"`
					ReapplyError string `json:"reapplyError"`
				}
				if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
					t.Fatal(err)
				}
				if rec.Code != http.StatusInternalServerError || body.Error == "" || body.Detail == "" || !body.Restored || body.Reapplied == failRestore || (failRestore && body.ReapplyError == "") {
					t.Fatalf("response: %d %s", rec.Code, rec.Body)
				}
				assertConfigResponseHeader(t, rec, "")
				if len(rec.Header().Values("X-Containd-Warnings")) != 0 {
					t.Fatal("rules failure became a warning")
				}
				got, err := store.Load(ctx)
				if err != nil || !reflect.DeepEqual(jsonValue(t, got), jsonValue(t, running)) {
					t.Fatalf("running not restored: %v %+v", err, got)
				}
				stagedSnapshot2, err := store.ReadSnapshot(ctx, config.SnapshotCandidate, true)
				staged := stagedSnapshot2.Candidate
				if err != nil || !reflect.DeepEqual(jsonValue(t, staged), jsonValue(t, candidate)) {
					t.Fatalf("candidate changed: %v %+v", err, staged)
				}
				bank, err := store.LoadIDSRules(ctx)
				if err != nil || !reflect.DeepEqual(bank, running.IDS.Rules) {
					t.Fatalf("IDS bank changed: %v %+v", err, bank)
				}
				if len(engine.attempts) != 2 || engine.attempts[1].Default != rules.ActionAllow {
					t.Fatalf("restore not reapplied: %+v", engine.attempts)
				}
				rec = requestStage(t, server, "GET", "/health", nil)
				var health struct {
					Enforcement struct {
						State  string `json:"state"`
						Reason string `json:"reason"`
					} `json:"enforcement"`
				}
				if err := json.Unmarshal(rec.Body.Bytes(), &health); err != nil {
					t.Fatal(err)
				}
				wantState := "enforcing"
				if failRestore {
					wantState = "unavailable"
				}
				if health.Enforcement.State != wantState || (health.Enforcement.Reason != "") != failRestore {
					t.Fatalf("health: %s", rec.Body)
				}
				if failRestore {
					engine.failRestore = false
					if _, err := ApplyRunningConfig(ctx, store, engine, nil); err != nil {
						t.Fatal(err)
					}
					fault, err := store.RuntimeApplyFault(ctx)
					if err != nil || fault != "" {
						t.Fatalf("replay failed to clear health: %q %v", fault, err)
					}
				}
			})
		}
	}
}

func TestDataplaneFailureCannotCommitAsWarning(t *testing.T) {
	store := stageStore(t)
	engine := &transactionalEngine{mockEngine: &mockEngine{}, configureErr: errors.New("dataplane unavailable")}
	server := NewServerWithEngine(store, nil, engine)
	rec := requestStage(t, server, "POST", "/config/commit", nil)
	if rec.Code != http.StatusInternalServerError || len(engine.attempts) != 0 {
		t.Fatalf("response: %d %s", rec.Code, rec.Body)
	}
}

func TestReplayNftFailureIsNotSuccess(t *testing.T) {
	for _, boot := range []bool{false, true} {
		store := stageStore(t)
		engine := &transactionalEngine{mockEngine: &mockEngine{}, failRestore: true}
		apply := ApplyRunningConfig
		if boot {
			apply = ApplyBootConfig
		}
		warnings, err := apply(context.Background(), store, engine, nil)
		if err == nil || len(warnings) != 0 {
			t.Fatalf("boot=%v warnings=%v err=%v", boot, warnings, err)
		}
		fault, err := store.RuntimeApplyFault(context.Background())
		if err != nil || fault == "" {
			t.Fatalf("replay fault missing: %q %v", fault, err)
		}
	}
}

func TestRunningChangeRequiresEngine(t *testing.T) {
	store := stageStore(t)
	server := NewServer(store, nil)
	rec := requestStage(t, server, "POST", "/config/commit", nil)
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("engine-less commit: %d %s", rec.Code, rec.Body)
	}
}

func TestCommitConfirmedRejectsDurationOverflow(t *testing.T) {
	store := stageStore(t)
	engine := &mockEngine{}
	server := NewServerWithEngine(store, nil, engine)
	rec := requestStage(t, server, "POST", "/config/commit_confirmed", map[string]int64{"ttl_seconds": 1<<63 - 1})
	if rec.Code != http.StatusBadRequest || engine.applied {
		t.Fatalf("overflow: %d %s", rec.Code, rec.Body)
	}
}

type failedCommitReader struct{}

func (failedCommitReader) Read([]byte) (int, error) { return 0, errors.New("body read failed") }

func TestCommitConfirmedRejectsUnreadableRequest(t *testing.T) {
	store := stageStore(t)
	engine := &mockEngine{}
	server := NewServerWithEngine(store, nil, engine)
	rec := httptest.NewRecorder()
	serveWithConfigRevision(t, server, rec, authedRequest(http.MethodPost, "/api/v1/config/commit_confirmed", failedCommitReader{}))
	if rec.Code != http.StatusBadRequest || engine.applied {
		t.Fatalf("unreadable request: %d %s", rec.Code, rec.Body)
	}
}
