// SPDX-License-Identifier: Apache-2.0
package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/tonylturner/containd/pkg/app/convergence"
	"github.com/tonylturner/containd/pkg/common/protection"

	engineclient "github.com/tonylturner/containd/api/engine"
	"github.com/tonylturner/containd/pkg/cp/config"
	"github.com/tonylturner/containd/pkg/cp/users"
	dpengine "github.com/tonylturner/containd/pkg/dp/engine"
	"github.com/tonylturner/containd/pkg/dp/rules"
)

type protectionEngine struct {
	*mockEngine
	observation         dpengine.ProtectionStatus
	healthErr, retryErr error
	phases              []string
	ids                 []string
	failFirst, omit     bool
	retryCalls          int
}

func (e *protectionEngine) ConfigureServices(ctx context.Context, admission protection.Admission, _ config.ServicesConfig) error {
	e.phases = append(e.phases, string(admission.ApplyID))
	return nil
}
func (e *protectionEngine) Configure(ctx context.Context, admission protection.Admission, _ config.DataPlaneConfig) error {
	e.phases = append(e.phases, string(admission.ApplyID))
	return nil
}
func (e *protectionEngine) ApplyRules(ctx context.Context, admission protection.Admission, _ rules.Snapshot) error {
	id := string(admission.ApplyID)
	e.phases = append(e.phases, id)
	e.ids = append(e.ids, id)
	if e.failFirst && len(e.ids) == 1 {
		return errors.New("apply_superseded: application was superseded")
	}
	if e.omit {
		return nil
	}
	st := cannedProtection("pending")
	st.ApplyID = id
	st.RunningRevision = admission.RunningRevision
	st.Mode = admission.Mode
	e.observation = st
	return nil
}
func (e *protectionEngine) RuntimeHealth(context.Context) (engineclient.RuntimeHealth, error) {
	return engineclient.RuntimeHealth{BootID: "boot", Protection: e.observation}, e.healthErr
}
func (e *protectionEngine) Retry(_ context.Context, admission protection.Admission) error {
	e.retryCalls++
	return e.retryErr
}
func (e *protectionEngine) Observe(ctx context.Context) (convergence.Observation, error) {
	h, err := e.RuntimeHealth(ctx)
	return convergence.Observation{BootID: protection.BootID(h.BootID), Engine: h.Protection.Observation(), Outcomes: h.Protection.Subsystems, Retryable: h.Protection.Retryable}, err
}
func cannedProtection(state string) dpengine.ProtectionStatus {
	return dpengine.ProtectionStatus{BootID: "boot", ApplyID: "apply", InstalledApplyID: "apply", State: state, ObservedAt: time.Now().UTC(), Retryable: true,
		Components: []dpengine.ProtectionComponent{{Name: "nfqueue:101", State: "failed", Reason: "private nft source 192.0.2.7", Since: time.Now()}}, Effects: []dpengine.ProtectionEffect{}}
}

func TestProtectionHealthMappingAndSanitization(t *testing.T) {
	for _, tc := range []struct{ state, want, reason string }{
		{"protecting", "enforcing", ""}, {"pending", "unavailable", "protection pending"}, {"failed", "unavailable", "protection failed"},
		{"degraded", "degraded", "rule-hit logging unavailable; nft policy enforcing"}, {"disabled", "disabled", ""}, {"unknown", "unknown", "engine protection status unavailable"},
	} {
		t.Run(tc.state, func(t *testing.T) {
			store := stageStore(t)
			cfg, err := store.Load(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			cfg.DataPlane.Enforcement = true
			if err := store.Save(context.Background(), cfg); err != nil {
				t.Fatal(err)
			}
			engine := &protectionEngine{mockEngine: &mockEngine{}, observation: cannedProtection(tc.state)}
			router := newTestServerWithEngine(store, nil, engine)
			rec := httptest.NewRecorder()
			router.ServeHTTP(rec, httptest.NewRequest("GET", "/api/v1/health", nil))
			var body struct {
				Enforcement struct{ State, Reason string }
				Protection  map[string]any
			}
			if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
				t.Fatal(err)
			}
			if rec.Code != 200 || body.Enforcement.State != tc.want || body.Enforcement.Reason != tc.reason || len(body.Protection) != 2 || body.Protection["applyId"] != "apply" {
				t.Fatalf("health: %d %s", rec.Code, rec.Body)
			}
			if strings.Contains(rec.Body.String(), "nfqueue") || strings.Contains(rec.Body.String(), "private") {
				t.Fatalf("diagnostics leaked: %s", rec.Body)
			}
			if err := store.SetRuntimeApplyFault(context.Background(), testRunningRevision(store), "private fault"); err != nil {
				t.Fatal(err)
			}
			rec = httptest.NewRecorder()
			router.ServeHTTP(rec, httptest.NewRequest("GET", "/api/v1/health", nil))
			if !strings.Contains(rec.Body.String(), "runtime synchronization is uncertain") {
				t.Fatalf("fault precedence: %s", rec.Body)
			}
		})
	}
	// A healthy protection observation never masks schedule planner degradation.
	cfg := config.DefaultConfig()
	got := enforcementHealth(config.HealthSnapshot{Config: cfg}, nil, rulesetObservation{status: dpengine.RulesetStatus{SchedulePlanner: &dpengine.SchedulePlan{State: dpengine.SchedulePlannerDegraded}}}, cannedProtection("protecting"))
	if got["state"] != "degraded" {
		t.Fatalf("planner precedence: %v", got)
	}
	for _, reason := range []string{"schedule refill failing", "schedule horizon exhausted", "schedule horizon ends within an hour", "private nft text"} {
		got := enforcementHealth(config.HealthSnapshot{Config: cfg}, nil, rulesetObservation{status: dpengine.RulesetStatus{SchedulePlanner: &dpengine.SchedulePlan{State: dpengine.SchedulePlannerDegraded, Reason: reason}}}, cannedProtection("protecting"))
		want := reason
		if reason == "private nft text" {
			want = "schedule planner degraded"
		}
		if got["reason"] != want {
			t.Fatalf("planner reason: %v want %s", got, want)
		}
	}
}

func TestProtectionRoutesAndRetryAudit(t *testing.T) {
	auditStore := &mockAuditStore{}
	engine := &protectionEngine{mockEngine: &mockEngine{}, observation: cannedProtection("failed")}
	store := stageStore(t)
	coordinator := testCoordinator(t, store, engine, nil)
	result, err := coordinator.Replay(context.Background(), false)
	if err != nil {
		t.Fatal(err)
	}
	server := NewServerWithEngineAndServices(store, auditStore, engine, &stageServices{}, nil, coordinator)
	body := map[string]string{"bootId": "boot", "applyId": string(result.ApplyID), "desiredRevision": string(result.RunningRevision)}
	for range 2 {
		rec := requestStage(t, server, "POST", "/dataplane/protection/retry", body)
		if rec.Code != 202 {
			t.Fatalf("coalesced retry: %d %s", rec.Code, rec.Body)
		}
	}
	if engine.retryCalls != 0 {
		t.Fatal("HTTP handler ran a second orchestration path")
	}
	body["desiredRevision"] += "_stale"
	rec := requestStage(t, server, "POST", "/dataplane/protection/retry", body)
	if rec.Code != 409 || !strings.Contains(rec.Body.String(), "protection_superseded") {
		t.Fatalf("stale retry: %d %s", rec.Code, rec.Body)
	}
	for _, invalid := range []string{`{}`, `{"bootId":"boot","applyId":"apply"}`, `{"bootId":"boot","applyId":"apply","desiredRevision":"running","extra":true}`, `{} {}`} {
		rec = httptest.NewRecorder()
		server.ServeHTTP(rec, authedRequest("POST", "/api/v1/dataplane/protection/retry", strings.NewReader(invalid)))
		if rec.Code != 400 {
			t.Fatalf("invalid retry: %d %s", rec.Code, rec.Body)
		}
	}
	if len(auditStore.records) != 3 {
		t.Fatalf("retry audits: %+v", auditStore.records)
	}
	for _, record := range auditStore.records {
		if record.Action != "dataplane.protection.retry" {
			t.Fatal(record)
		}
	}
	rec = requestStage(t, server, "GET", "/dataplane/protection", nil)
	if rec.Code != 200 || !strings.Contains(rec.Body.String(), "nfqueue:101") {
		t.Fatalf("authenticated diagnostics: %d %s", rec.Code, rec.Body)
	}
	engine.healthErr = errors.New("unreachable")
	rec = requestStage(t, server, "GET", "/dataplane/protection", nil)
	if rec.Code != 502 || !strings.Contains(rec.Body.String(), `"ready":false`) {
		t.Fatalf("unreachable: %d %s", rec.Code, rec.Body)
	}
	engine.healthErr = nil
	t.Setenv("CONTAIND_AUDITOR_TOKEN", "reader")
	server = NewServerWithEngineAndServices(store, auditStore, engine, &stageServices{}, nil, coordinator)
	for _, tc := range []struct {
		token string
		code  int
	}{{"", 401}, {"reader", 403}} {
		req := httptest.NewRequest("POST", "/api/v1/dataplane/protection/retry", strings.NewReader(`{}`))
		if tc.token != "" {
			req.Header.Set("Authorization", "Bearer "+tc.token)
		}
		rec = httptest.NewRecorder()
		server.ServeHTTP(rec, req)
		if rec.Code != tc.code {
			t.Fatalf("authorization: %d", rec.Code)
		}
	}
	req := httptest.NewRequest("GET", "/api/v1/dataplane/protection", nil)
	req.Header.Set("Authorization", "Bearer reader")
	rec = httptest.NewRecorder()
	server.ServeHTTP(rec, req)
	if rec.Code != 200 {
		t.Fatalf("reader: %d %s", rec.Code, rec.Body)
	}
	unavailable := newTestServerWithEngine(stageStore(t), nil, nil)
	rec = requestStage(t, unavailable, "GET", "/dataplane/protection", nil)
	if rec.Code != 502 || !strings.Contains(rec.Body.String(), `"ready":false`) {
		t.Fatalf("missing engine: %d %s", rec.Code, rec.Body)
	}
}

func TestProtectionApplyIdentitiesAndBodies(t *testing.T) {
	for _, omit := range []bool{false, true} {
		t.Run(map[bool]string{true: "missing observation", false: "observation"}[omit], func(t *testing.T) {
			store := stageStore(t)
			cfg, err := store.Load(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			cfg.DataPlane.Enforcement = true
			if err := store.Save(context.Background(), cfg); err != nil {
				t.Fatal(err)
			}
			engine := &protectionEngine{mockEngine: &mockEngine{}, omit: omit}
			server := newTestServerWithEngine(store, nil, engine)
			seen := map[string]bool{}
			for _, path := range []string{"/config/commit", "/config/commit_confirmed", "/config/rollback"} {
				rec := requestStage(t, server, "POST", path, nil)
				var body struct {
					Status, ApplyID string
					Protection      dpengine.ProtectionStatus
				}
				if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
					t.Fatal(err)
				}
				if rec.Code != 200 || body.ApplyID == "" || seen[body.ApplyID] || (!omit && body.Protection.ApplyID != body.ApplyID) {
					t.Fatalf("body: %d %s", rec.Code, rec.Body)
				}
				seen[body.ApplyID] = true
				state := "pending"
				if omit {
					state = "unknown"
				}
				if body.Protection.State != state || rec.Header().Get("X-Containd-Revision") == "" {
					t.Fatalf("observation: %s", rec.Body)
				}
			}
			rec := requestStage(t, server, "POST", "/config/confirm", nil)
			if rec.Code != 200 || strings.Contains(rec.Body.String(), "applyId") || len(engine.ids) != 3 {
				t.Fatalf("confirm changed runtime or shape: %d %s ids=%v", rec.Code, rec.Body, engine.ids)
			}
			for i := 0; i < len(engine.phases); i += 3 {
				if engine.phases[i] == "" || engine.phases[i] != engine.phases[i+1] || engine.phases[i] != engine.phases[i+2] {
					t.Fatalf("phase IDs: %v", engine.phases)
				}
			}
			for i := 0; i < 2; i++ {
				if _, err := replayTestConfig(context.Background(), store, engine, nil); err != nil {
					t.Fatal(err)
				}
			}
			if engine.ids[len(engine.ids)-1] == engine.ids[len(engine.ids)-2] {
				t.Fatal("replay reused identity")
			}
		})
	}
}

func TestProtectionCompensationAndRecoveryIdentities(t *testing.T) {
	store := stageStore(t)
	before := testRunningRevision(store)
	engine := &protectionEngine{mockEngine: &mockEngine{}, failFirst: true}
	server := newTestServerWithEngine(store, nil, engine)
	rec := requestStage(t, server, "POST", "/config/commit", nil)
	if rec.Code != 500 || !strings.Contains(rec.Body.String(), "apply_superseded") || len(engine.ids) != 2 || engine.ids[0] == engine.ids[1] {
		t.Fatalf("compensation: %d %s ids=%v", rec.Code, rec.Body, engine.ids)
	}
	restored := testRunningRevision(store)
	if restored == before || engine.observation.RunningRevision != protection.Revision(restored) {
		t.Fatal("compensation reused an earlier running generation")
	}
	if err := store.SetManagementBootFault(context.Background(), "refused"); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 2; i++ {
		if _, err := replayTestConfig(context.Background(), store, engine, nil); err != nil {
			t.Fatal(err)
		}
	}
	if len(engine.ids) != 4 || engine.ids[2] == engine.ids[3] {
		t.Fatalf("recovery reused identity: %v", engine.ids)
	}
}

func TestProtectionFactoryResetBody(t *testing.T) {
	store := stageStore(t)
	us, err := users.NewSQLiteStore(filepath.Join(t.TempDir(), "users.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer us.Close()
	engine := &protectionEngine{mockEngine: &mockEngine{}}
	server := NewServerWithEngineAndServices(store, nil, engine, &stageServices{}, us)
	rec := requestStage(t, server, "POST", "/system/factory-reset", json.RawMessage(`{"confirm":"NUCLEAR"}`))
	var body struct {
		Status, ApplyID string
		Protection      dpengine.ProtectionStatus
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if rec.Code != 200 || body.Status != "reset" || body.ApplyID == "" || body.Protection.ApplyID != body.ApplyID {
		t.Fatalf("reset: %d %s", rec.Code, rec.Body)
	}
	assertConfigResponseHeader(t, rec, "committed")
}
