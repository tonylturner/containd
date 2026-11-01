// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	engineclient "github.com/tonylturner/containd/api/engine"
	"github.com/tonylturner/containd/pkg/cp/config"
	"github.com/tonylturner/containd/pkg/dp/coverage"
	dpengine "github.com/tonylturner/containd/pkg/dp/engine"
	"github.com/tonylturner/containd/pkg/dp/netcfg"
)

func TestHealthReportsUnboundManagement(t *testing.T) {
	cfg := config.DefaultConfig()
	engine := &mockEngine{}
	server := NewServerWithEngine(&mockStore{cfg: cfg}, nil, engine)
	check := func(want string) {
		t.Helper()
		rec := httptest.NewRecorder()
		serveWithConfigRevision(t, server, rec, httptest.NewRequest(http.MethodGet, "/api/v1/health", nil))
		var body struct {
			Binding struct {
				State string `json:"state"`
				Ports []int  `json:"recoveryPorts"`
			} `json:"managementBinding"`
		}
		if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
			t.Fatal(err)
		}
		if rec.Code != 200 || body.Binding.State != want || (want == "unbound-appliance" && len(body.Binding.Ports) == 0) {
			t.Fatalf("health = %s", rec.Body)
		}
	}
	check("unbound-appliance")
	cfg.Interfaces[0].Device = "eth0"
	check("configured")
	engine.state = []config.InterfaceState{{Name: "eth0", Up: false}, {Name: "eth1", Up: true}}
	check("configured") // Administrative link-down is not an unbound appliance.
	off := false
	for i := range cfg.Interfaces {
		cfg.Interfaces[i].Access = config.InterfaceAccess{Mgmt: &off, HTTP: &off, HTTPS: &off, SSH: &off}
	}
	check("configured")
}

type healthMockEngine struct {
	*mockEngine
	st         dpengine.IEC104Enforcement
	forwarding netcfg.IPv4ForwardingStatus
	err        error
}

func (m *healthMockEngine) RuntimeHealth(context.Context) (engineclient.RuntimeHealth, error) {
	return engineclient.RuntimeHealth{
		IEC104Enforcement: m.st,
		IPv4Forwarding:    m.forwarding,
	}, m.err
}

func healthBody(t *testing.T, engine EngineClient) (int, map[string]any) {
	t.Helper()
	s := NewServerWithEngine(&mockStore{}, nil, engine)
	rec := httptest.NewRecorder()
	req, _ := http.NewRequest(http.MethodGet, "/api/v1/health", nil)
	serveWithConfigRevision(t, s, rec, req)
	var body map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
	return rec.Code, body
}

func TestHealthReportsIEC104Enforcement(t *testing.T) {
	cases := []struct {
		name       string
		engine     EngineClient
		want       map[string]any
		forwarding netcfg.IPv4ForwardingStatus
	}{
		{
			name:       "no engine",
			forwarding: netcfg.IPv4ForwardingUnknown,
			want:       map[string]any{"active": false, "healthy": false, "reason": "engine unreachable"},
		},
		{
			name:       "engine error",
			engine:     &healthMockEngine{mockEngine: &mockEngine{}, err: errors.New("connection refused")},
			forwarding: netcfg.IPv4ForwardingUnknown,
			want:       map[string]any{"active": false, "healthy": false, "reason": "engine unreachable"},
		},
		{
			name:       "engine unhealthy",
			engine:     &healthMockEngine{mockEngine: &mockEngine{}, st: dpengine.IEC104Enforcement{Active: true, Reason: "reset injector unavailable"}},
			forwarding: netcfg.IPv4ForwardingUnknown,
			want:       map[string]any{"active": true, "healthy": false, "reason": "IEC104 enforcement unavailable"},
		},
		{
			name:       "inactive",
			engine:     &healthMockEngine{mockEngine: &mockEngine{}, st: dpengine.IEC104Enforcement{Healthy: true}},
			forwarding: netcfg.IPv4ForwardingUnknown,
			want:       map[string]any{"active": false, "healthy": true, "reason": ""},
		},
		{
			name:       "forwarding enabled",
			engine:     &healthMockEngine{mockEngine: &mockEngine{}, forwarding: netcfg.IPv4ForwardingEnabled},
			forwarding: netcfg.IPv4ForwardingEnabled,
			want:       map[string]any{"active": false, "healthy": false, "reason": ""},
		},
		{
			name:       "forwarding disabled",
			engine:     &healthMockEngine{mockEngine: &mockEngine{}, forwarding: netcfg.IPv4ForwardingDisabled},
			forwarding: netcfg.IPv4ForwardingDisabled,
			want:       map[string]any{"active": false, "healthy": false, "reason": ""},
		},
	}
	for _, c := range cases {
		code, body := healthBody(t, c.engine)
		if code != http.StatusOK || body["status"] != "ok" {
			t.Fatalf("%s: liveness = %d %v", c.name, code, body)
		}
		got, _ := body["iec104Enforcement"].(map[string]any)
		if !reflect.DeepEqual(got, c.want) {
			t.Fatalf("%s: iec104Enforcement = %v, want exactly %v", c.name, got, c.want)
		}
		if body["ipv4Forwarding"] != string(c.forwarding) {
			t.Fatalf("%s: ipv4Forwarding = %v, want %q", c.name, body["ipv4Forwarding"], c.forwarding)
		}
	}
}

func TestRulesetHealthDoesNotExposePolicyDiagnostics(t *testing.T) {
	store := stageStore(t)
	sensitive := "nft apply failed: secret source 192.0.2.44 tcp dport 12345"
	if err := store.SetRuntimeApplyFault(context.Background(), sensitive); err != nil {
		t.Fatal(err)
	}
	engine := &mockEngine{ruleset: dpengine.RulesetStatus{Error: sensitive}}
	snapshot, err := store.ReadHealthSnapshot(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	health := enforcementHealth(snapshot, nil, observeRuleset(context.Background(), engine), dpengine.ProtectionStatus{State: "protecting"})
	if health["state"] != "unavailable" || health["reason"] == "" || len(health) != 2 {
		t.Fatalf("health fault hidden or shape changed: %v", health)
	}
	if strings.Contains(health["reason"].(string), "192.0.2.44") || strings.Contains(health["reason"].(string), "12345") {
		t.Fatalf("unauthenticated health exposes policy: %v", health)
	}
}

type healthRulesetEngine struct {
	*mockEngine
	err error
}

func (e *healthRulesetEngine) RulesetStatus(ctx context.Context) (dpengine.RulesetStatus, error) {
	if err := ctx.Err(); err != nil {
		return dpengine.RulesetStatus{}, err
	}
	return e.ruleset, e.err
}

func TestHealthEnforcementStates(t *testing.T) {
	for _, tc := range []struct {
		name        string
		enabled     bool
		fault       string
		snapshotErr error
		status      dpengine.RulesetStatus
		engineErr   error
		protection  string
		want        string
	}{
		{name: "disabled", protection: "disabled", want: "disabled"},
		{name: "enforcing", enabled: true, status: dpengine.RulesetStatus{Ruleset: "rules", AppliedAt: time.Now()}, protection: "protecting", want: "enforcing"},
		{name: "not applied", enabled: true, protection: "pending", want: "unavailable"},
		{name: "failed ruleset", enabled: true, status: dpengine.RulesetStatus{Error: "private nft diagnostic"}, protection: "failed", want: "unavailable"},
		{name: "protection authoritative over stale ruleset error", enabled: true, status: dpengine.RulesetStatus{Ruleset: "rules", AppliedAt: time.Now(), Error: "private nft diagnostic"}, protection: "protecting", want: "enforcing"},
		{name: "schedule planner degraded", enabled: true, status: dpengine.RulesetStatus{Ruleset: "rules", AppliedAt: time.Now(),
			SchedulePlanner: &dpengine.SchedulePlan{State: dpengine.SchedulePlannerDegraded, Reason: "schedule refill failing", LastError: "private nft diagnostic"}}, protection: "protecting", want: "degraded"},
		{name: "schedule planner ok", enabled: true, status: dpengine.RulesetStatus{Ruleset: "rules", AppliedAt: time.Now(),
			SchedulePlanner: &dpengine.SchedulePlan{State: dpengine.SchedulePlannerOK}}, protection: "protecting", want: "enforcing"},
		{name: "persisted fault", enabled: true, fault: "private replay diagnostic", protection: "protecting", want: "unavailable"},
		{name: "failed disable", fault: "private replay diagnostic", protection: "disabled", want: "unavailable"},
		{name: "store busy", snapshotErr: config.ErrHealthBusy, protection: "protecting", want: "unknown"},
		{name: "engine unreadable", enabled: true, engineErr: context.DeadlineExceeded, protection: "unknown", want: "unknown"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := config.DefaultConfig()
			cfg.DataPlane.Enforcement = tc.enabled
			engine := &healthRulesetEngine{mockEngine: &mockEngine{ruleset: tc.status}, err: tc.engineErr}

			health := enforcementHealth(config.HealthSnapshot{Config: cfg, ApplyFault: tc.fault}, tc.snapshotErr, observeRuleset(context.Background(), engine), dpengine.ProtectionStatus{State: tc.protection})
			if health["state"] != tc.want || len(health) != 2 {
				t.Fatalf("health: %v want %s", health, tc.want)
			}
			wantReason := tc.want != "enforcing" && tc.want != "disabled"
			if (health["reason"] != "") != wantReason || strings.Contains(health["reason"].(string), "private") {
				t.Fatalf("reason: %v", health)
			}
		})
	}
}

func TestHealthWaitsForBriefStoreOperation(t *testing.T) {
	store := stageStore(t)
	ctx := context.Background()
	cfg, err := store.Load(ctx)
	if err != nil {
		t.Fatal(err)
	}
	cfg.DataPlane.Enforcement = true
	cfg.Interfaces[0].Device = "eth0"
	if err := store.Save(ctx, cfg); err != nil {
		t.Fatal(err)
	}
	entered, release := make(chan struct{}), make(chan struct{})
	var once sync.Once
	unblock := func() { once.Do(func() { close(release) }) }
	defer unblock()
	mutated := make(chan error, 1)
	go func() {
		mutated <- testMutateCandidate(store, ctx, func(candidate *config.Config) error {
			close(entered)
			<-release
			candidate.System.Hostname = "candidate-only"
			return nil
		})
	}()
	<-entered
	engine := &mockEngine{
		state:   []config.InterfaceState{{Name: "eth0"}},
		ruleset: dpengine.RulesetStatus{Ruleset: "rules", AppliedAt: time.Now()},
	}
	server := NewServerWithEngine(store, nil, engine)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/v1/health", nil)
	started := time.Now()
	timer := time.AfterFunc(50*time.Millisecond, unblock)
	defer timer.Stop()
	serveWithConfigRevision(t, server, rec, req)
	elapsed := time.Since(started)
	if elapsed < 50*time.Millisecond || elapsed > engineHealthTimeout+100*time.Millisecond {
		t.Fatalf("health did not wait within budget: %s", elapsed)
	}
	var body struct {
		Enforcement struct {
			State string `json:"state"`
		} `json:"enforcement"`
		Binding struct {
			State string `json:"state"`
		} `json:"managementBinding"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if rec.Code != http.StatusOK || body.Enforcement.State != "enforcing" || body.Binding.State != "configured" {
		t.Fatalf("brief contention hid real state: %d %s", rec.Code, rec.Body)
	}
	if err := <-mutated; err != nil {
		t.Fatal(err)
	}
}

func TestHealthAnswersDuringRunningApplyWithoutExposingPromotion(t *testing.T) {
	store := stageStore(t)
	ctx := context.Background()
	candidate, err := store.Load(ctx)
	if err != nil {
		t.Fatal(err)
	}
	candidate.System.Hostname = "not-yet-applied"
	candidate.DataPlane.Enforcement = true
	if err := testSaveCandidate(store, ctx, candidate); err != nil {
		t.Fatal(err)
	}
	entered, release := make(chan struct{}), make(chan struct{})
	var once sync.Once
	unblock := func() { once.Do(func() { close(release) }) }
	defer unblock()
	applied := make(chan error, 1)
	go func() {
		applied <- testApplyChange(store, ctx, config.ChangeCommit, 0, func(context.Context, *config.Config, *config.Config) error {
			close(entered)
			<-release
			return nil
		})
	}()
	<-entered
	readCtx, cancel := context.WithTimeout(ctx, 20*time.Millisecond)
	defer cancel()
	snapshot, err := store.ReadHealthSnapshot(readCtx)
	if !errors.Is(err, config.ErrHealthBusy) || !errors.Is(err, context.DeadlineExceeded) || snapshot.Config != nil {
		t.Fatalf("intermediate health snapshot exposed: %+v %v", snapshot, err)
	}
	loaded := make(chan *config.Config, 1)
	loadError := make(chan error, 1)
	go func() { cfg, err := store.Load(ctx); loaded <- cfg; loadError <- err }()
	select {
	case cfg := <-loaded:
		t.Fatalf("reader observed unapplied config: %+v", cfg)
	case <-time.After(20 * time.Millisecond):
	}
	server := NewServerWithEngine(store, nil, &mockEngine{})
	rec := httptest.NewRecorder()
	answered := make(chan struct{})
	start := time.Now()
	go func() {
		serveWithConfigRevision(t, server, rec, httptest.NewRequest(http.MethodGet, "/api/v1/health", nil))
		close(answered)
	}()
	select {
	case <-answered:
	case <-time.After(engineHealthTimeout + 100*time.Millisecond):
		t.Fatal("health blocked on running apply")
	}
	if elapsed := time.Since(start); elapsed < engineHealthTimeout || elapsed > engineHealthTimeout+100*time.Millisecond {
		t.Fatalf("health did not use the shared observation budget: %s", elapsed)
	}
	var body struct {
		Enforcement struct {
			State string `json:"state"`
		} `json:"enforcement"`
		Binding struct {
			State string `json:"state"`
		} `json:"managementBinding"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if rec.Code != http.StatusOK || body.Enforcement.State != "unknown" || body.Binding.State != "unknown" {
		t.Fatalf("health: %d %s", rec.Code, rec.Body)
	}
	unblock()
	if err := <-applied; err != nil {
		t.Fatal(err)
	}
	if cfg := <-loaded; cfg == nil || cfg.System.Hostname != candidate.System.Hostname {
		t.Fatalf("applied running: %+v", cfg)
	}
	if err := <-loadError; err != nil {
		t.Fatal(err)
	}
}

type deadlineHealthEngine struct {
	*mockEngine
	deadlines []time.Time
	stall     bool
}

func (e *deadlineHealthEngine) observe(ctx context.Context) error {
	deadline, _ := ctx.Deadline()
	e.deadlines = append(e.deadlines, deadline)
	return ctx.Err()
}
func (e *deadlineHealthEngine) RuntimeHealth(ctx context.Context) (engineclient.RuntimeHealth, error) {
	err := e.observe(ctx)
	if e.stall {
		<-ctx.Done()
		err = ctx.Err()
	}
	return engineclient.RuntimeHealth{}, err
}
func (e *deadlineHealthEngine) RulesetStatus(ctx context.Context) (dpengine.RulesetStatus, error) {
	return e.ruleset, e.observe(ctx)
}
func (e *deadlineHealthEngine) ListInterfaceState(ctx context.Context) ([]config.InterfaceState, error) {
	return nil, e.observe(ctx)
}

func TestHealthSharesOneObservationDeadline(t *testing.T) {
	for _, stall := range []bool{false, true} {
		t.Run(map[bool]string{false: "readable", true: "timed out"}[stall], func(t *testing.T) {
			cfg := config.DefaultConfig()
			cfg.DataPlane.Enforcement = true
			engine := &deadlineHealthEngine{mockEngine: &mockEngine{ruleset: dpengine.RulesetStatus{Ruleset: "rules", AppliedAt: time.Now()}}, stall: stall}
			server := NewServerWithEngine(&mockStore{cfg: cfg}, nil, engine)
			ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
			defer cancel()
			rec := httptest.NewRecorder()
			started := time.Now()
			serveWithConfigRevision(t, server, rec, httptest.NewRequest(http.MethodGet, "/api/v1/health", nil).WithContext(ctx))
			if rec.Code != http.StatusOK || time.Since(started) >= engineHealthTimeout {
				t.Fatalf("late liveness: %d %s", rec.Code, rec.Body)
			}
			if len(engine.deadlines) != 3 {
				t.Fatalf("observations: %v", engine.deadlines)
			}
			for _, deadline := range engine.deadlines {
				if deadline.IsZero() || !deadline.Equal(engine.deadlines[0]) {
					t.Fatalf("observation budgets differ: %v", engine.deadlines)
				}
			}
			if stall {
				var body struct {
					Enforcement struct {
						State string `json:"state"`
					} `json:"enforcement"`
					Binding struct {
						State string `json:"state"`
					} `json:"managementBinding"`
				}
				if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
					t.Fatal(err)
				}
				if body.Enforcement.State != "unknown" || body.Binding.State != "unknown" {
					t.Fatalf("timed out observation reported known: %s", rec.Body)
				}
			}
		})
	}
}

func TestHealthReportsICSEnforcementCounts(t *testing.T) {
	applied := []coverage.Rule{
		{RuleID: "secret-rule-a", Protocol: "modbus", Mode: "enforce", State: coverage.Enforcing},
		{RuleID: "secret-rule-b", Protocol: "dnp3", Mode: "enforce", State: coverage.Partial,
			Reasons: []coverage.Reason{{Code: coverage.ExclusionOverlap, Value: "192.0.2.44", Message: "excluded"}}},
		{RuleID: "secret-rule-c", Protocol: "modbus", Mode: "monitor", State: coverage.Monitoring},
	}
	for _, tc := range []struct {
		name   string
		engine EngineClient
		want   map[string]any
	}{
		{"no engine", nil, map[string]any{"state": "unknown", "enforcing": 0.0, "partial": 0.0, "notEnforcing": 0.0, "monitoring": 0.0}},
		{"engine error", &healthRulesetEngine{mockEngine: &mockEngine{}, err: errors.New("refused")},
			map[string]any{"state": "unknown", "enforcing": 0.0, "partial": 0.0, "notEnforcing": 0.0, "monitoring": 0.0}},
		{"no semantic rule", &mockEngine{}, map[string]any{"state": "none", "enforcing": 0.0, "partial": 0.0, "notEnforcing": 0.0, "monitoring": 0.0}},
		{"worst enforce state", &mockEngine{ruleset: dpengine.RulesetStatus{ICSCoverage: applied}},
			map[string]any{"state": "partial", "enforcing": 1.0, "partial": 1.0, "notEnforcing": 0.0, "monitoring": 1.0}},
		{"learn only", &mockEngine{ruleset: dpengine.RulesetStatus{ICSCoverage: applied[2:]}},
			map[string]any{"state": "monitoring", "enforcing": 0.0, "partial": 0.0, "notEnforcing": 0.0, "monitoring": 1.0}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			code, body := healthBody(t, tc.engine)
			if code != http.StatusOK {
				t.Fatalf("liveness = %d", code)
			}
			if got := body["icsEnforcement"]; !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("icsEnforcement = %v, want %v", got, tc.want)
			}
			raw, _ := json.Marshal(body)
			if strings.Contains(string(raw), "secret-rule") || strings.Contains(string(raw), "192.0.2.44") {
				t.Fatalf("unauthenticated health names rules or exclusions: %s", raw)
			}
		})
	}
}
