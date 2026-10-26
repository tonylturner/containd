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
		server.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/v1/health", nil))
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
	s.ServeHTTP(rec, req)
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
			want:       map[string]any{"active": true, "healthy": false, "reason": "reset injector unavailable"},
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
	health := enforcementHealth(context.Background(), snapshot, nil, engine)
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
		want        string
	}{
		{name: "disabled", want: "disabled"},
		{name: "enforcing", enabled: true, status: dpengine.RulesetStatus{Ruleset: "rules", AppliedAt: time.Now()}, want: "enforcing"},
		{name: "not applied", enabled: true, want: "unavailable"},
		{name: "failed ruleset", enabled: true, status: dpengine.RulesetStatus{Error: "private nft diagnostic"}, want: "unavailable"},
		{name: "persisted fault", enabled: true, fault: "private replay diagnostic", want: "unavailable"},
		{name: "failed disable", fault: "private replay diagnostic", want: "unavailable"},
		{name: "store busy", snapshotErr: config.ErrHealthBusy, want: "unknown"},
		{name: "engine unreadable", enabled: true, engineErr: context.DeadlineExceeded, want: "unknown"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := config.DefaultConfig()
			cfg.DataPlane.Enforcement = tc.enabled
			engine := &healthRulesetEngine{mockEngine: &mockEngine{ruleset: tc.status}, err: tc.engineErr}
			health := enforcementHealth(context.Background(), config.HealthSnapshot{Config: cfg, ApplyFault: tc.fault}, tc.snapshotErr, engine)
			if health["state"] != tc.want || len(health) != 2 {
				t.Fatalf("health: %v want %s", health, tc.want)
			}
			wantReason := tc.want == "unknown" || tc.want == "unavailable"
			if (health["reason"] != "") != wantReason || strings.Contains(health["reason"].(string), "private") {
				t.Fatalf("reason: %v", health)
			}
		})
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
	if err := store.SaveCandidate(ctx, candidate); err != nil {
		t.Fatal(err)
	}
	entered, release := make(chan struct{}), make(chan struct{})
	var once sync.Once
	unblock := func() { once.Do(func() { close(release) }) }
	defer unblock()
	applied := make(chan error, 1)
	go func() {
		applied <- store.ApplyChange(ctx, config.ChangeCommit, 0, func(context.Context, *config.Config, *config.Config) error {
			close(entered)
			<-release
			return nil
		})
	}()
	<-entered
	snapshot, err := store.ReadHealthSnapshot(ctx)
	if !errors.Is(err, config.ErrHealthBusy) || snapshot.Config != nil {
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
		server.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/v1/health", nil))
		close(answered)
	}()
	select {
	case <-answered:
	case <-time.After(engineHealthTimeout):
		t.Fatal("health blocked on running apply")
	}
	if time.Since(start) >= engineHealthTimeout {
		t.Fatal("health exceeded observation budget")
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
			server.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/v1/health", nil).WithContext(ctx))
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
