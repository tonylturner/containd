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

func (e *protectionEngine) ConfigureServices(ctx context.Context, _ config.ServicesConfig) ([]string, error) {
	e.phases = append(e.phases, engineclient.ApplyID(ctx))
	return nil, nil
}
func (e *protectionEngine) Configure(ctx context.Context, _ config.DataPlaneConfig) error {
	e.phases = append(e.phases, engineclient.ApplyID(ctx))
	return nil
}
func (e *protectionEngine) ApplyRules(ctx context.Context, _ rules.Snapshot) (dpengine.ProtectionStatus, error) {
	id := engineclient.ApplyID(ctx)
	e.phases = append(e.phases, id)
	e.ids = append(e.ids, id)
	if e.failFirst && len(e.ids) == 1 {
		return dpengine.ProtectionStatus{}, errors.New("apply_superseded: application was superseded")
	}
	if e.omit {
		return dpengine.ProtectionStatus{}, nil
	}
	st := cannedProtection("pending")
	st.ApplyID = id
	return st, nil
}
func (e *protectionEngine) RuntimeHealth(context.Context) (engineclient.RuntimeHealth, error) {
	return engineclient.RuntimeHealth{BootID: "boot", Protection: e.observation}, e.healthErr
}
func (e *protectionEngine) RetryProtection(_ context.Context, bootID, applyID string) error {
	e.retryCalls++
	if bootID != "boot" || applyID != "apply" {
		return &engineclient.ProtectionConflict{Code: "protection_superseded"}
	}
	return e.retryErr
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
			engine := &protectionEngine{mockEngine: &mockEngine{}, observation: cannedProtection(tc.state)}
			router := NewServerWithEngine(store, nil, engine)
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
			if err := store.SetRuntimeApplyFault(context.Background(), "private fault"); err != nil {
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
	for _, tc := range []struct {
		name, body string
		err        error
		code       int
		conflict   string
	}{
		{name: "accepted", body: `{"bootId":"boot","applyId":"apply"}`, code: 202},
		{name: "superseded", body: `{"bootId":"old","applyId":"apply"}`, code: 409, conflict: "protection_superseded"},
		{name: "not retryable", body: `{"bootId":"boot","applyId":"apply"}`, err: &engineclient.ProtectionConflict{Code: "protection_not_retryable"}, code: 409, conflict: "protection_not_retryable"},
		{name: "unreachable", body: `{"bootId":"boot","applyId":"apply"}`, err: errors.New("unreachable"), code: 502},
		{name: "invalid", body: `{}`, code: 400},
	} {
		t.Run(tc.name, func(t *testing.T) {
			auditStore := &mockAuditStore{}
			engine := &protectionEngine{mockEngine: &mockEngine{}, observation: cannedProtection("failed"), retryErr: tc.err}
			server := NewServerWithEngine(stageStore(t), auditStore, engine)
			rec := requestStage(t, server, "POST", "/dataplane/protection/retry", json.RawMessage(tc.body))
			if rec.Code != tc.code || tc.conflict != "" && !strings.Contains(rec.Body.String(), tc.conflict) {
				t.Fatalf("retry: %d %s", rec.Code, rec.Body)
			}
			if tc.code != 400 {
				if len(auditStore.records) != 1 || auditStore.records[0].Action != "dataplane.protection.retry" {
					t.Fatalf("audit: %+v", auditStore.records)
				}
			}
			rec = requestStage(t, server, "GET", "/dataplane/protection", nil)
			if rec.Code != 200 || !strings.Contains(rec.Body.String(), "nfqueue:101") {
				t.Fatalf("authenticated observation: %d %s", rec.Code, rec.Body)
			}
			engine.healthErr = errors.New("unreachable")
			rec = requestStage(t, server, "GET", "/dataplane/protection", nil)
			if rec.Code != 502 {
				t.Fatalf("unreachable: %d %s", rec.Code, rec.Body)
			}
		})
	}
	t.Setenv("CONTAIND_AUDITOR_TOKEN", "reader")
	engine := &protectionEngine{mockEngine: &mockEngine{}}
	server := NewServerWithEngine(stageStore(t), nil, engine)
	for _, tc := range []struct {
		token string
		code  int
	}{{"", 401}, {"reader", 403}} {
		req := httptest.NewRequest("POST", "/api/v1/dataplane/protection/retry", strings.NewReader(`{"bootId":"boot","applyId":"apply"}`))
		if tc.token != "" {
			req.Header.Set("Authorization", "Bearer "+tc.token)
		}
		rec := httptest.NewRecorder()
		server.ServeHTTP(rec, req)
		if rec.Code != tc.code || engine.retryCalls != 0 {
			t.Fatalf("authorization: %d calls=%d", rec.Code, engine.retryCalls)
		}
	}
	for _, token := range []string{"", "reader"} {
		req := httptest.NewRequest("GET", "/api/v1/dataplane/protection", nil)
		if token != "" {
			req.Header.Set("Authorization", "Bearer "+token)
		}
		rec := httptest.NewRecorder()
		server.ServeHTTP(rec, req)
		want := 200
		if token == "" {
			want = 401
		}
		if rec.Code != want {
			t.Fatalf("read authorization: %d %s", rec.Code, rec.Body)
		}
	}
	for _, method := range []string{"GET", "POST"} {
		path := "/dataplane/protection"
		if method == "POST" {
			path += "/retry"
		}
		server := NewServerWithEngine(stageStore(t), nil, nil)
		rec := requestStage(t, server, method, path, json.RawMessage(`{"bootId":"boot","applyId":"apply"}`))
		if rec.Code != 503 {
			t.Fatalf("no engine: %d %s", rec.Code, rec.Body)
		}
	}
}

func TestProtectionApplyIdentitiesAndBodies(t *testing.T) {
	for _, omit := range []bool{false, true} {
		t.Run(map[bool]string{true: "missing observation", false: "observation"}[omit], func(t *testing.T) {
			store := stageStore(t)
			engine := &protectionEngine{mockEngine: &mockEngine{}, omit: omit}
			server := NewServerWithEngine(store, nil, engine)
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
				if rec.Code != 200 || body.ApplyID == "" || seen[body.ApplyID] || body.Protection.ApplyID != body.ApplyID {
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
				if _, err := ApplyBootConfig(context.Background(), store, engine, nil); err != nil {
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
	engine := &protectionEngine{mockEngine: &mockEngine{}, failFirst: true}
	server := NewServerWithEngine(store, nil, engine)
	rec := requestStage(t, server, "POST", "/config/commit", nil)
	if rec.Code != 500 || !strings.Contains(rec.Body.String(), "apply_superseded") || len(engine.ids) != 2 || engine.ids[0] == engine.ids[1] {
		t.Fatalf("compensation: %d %s ids=%v", rec.Code, rec.Body, engine.ids)
	}
	if err := store.SetManagementBootFault(context.Background(), "refused"); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 2; i++ {
		if _, err := ApplyBootConfig(context.Background(), store, engine, nil); err != nil {
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
	server := NewServerWithEngineAndServices(store, nil, engine, nil, us)
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
