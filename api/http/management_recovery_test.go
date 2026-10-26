// SPDX-License-Identifier: Apache-2.0
package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/tonylturner/containd/pkg/cp/compile"
	"github.com/tonylturner/containd/pkg/cp/config"
	"github.com/tonylturner/containd/pkg/dp/enforce"
	dpengine "github.com/tonylturner/containd/pkg/dp/engine"
	"github.com/tonylturner/containd/pkg/dp/rules"
)

type recoveryEngine struct {
	*stageEngine
	dp        config.DataPlaneConfig
	snapshot  rules.Snapshot
	configErr error
	rulesErr  error
}

func (e *recoveryEngine) Configure(_ context.Context, dp config.DataPlaneConfig) error {
	e.dp = dp
	return e.configErr
}

func (e *recoveryEngine) ApplyRules(_ context.Context, snapshot rules.Snapshot) error {
	e.snapshot = snapshot
	return e.rulesErr
}

func TestManagementRecoveryApplyAndStatus(t *testing.T) {
	store, _ := reservedAPIStore(t)
	ctx := context.Background()
	if err := store.SetManagementBootFault(ctx, "stored conflict"); err != nil {
		t.Fatal(err)
	}
	engine := &recoveryEngine{stageEngine: &stageEngine{mockEngine: &mockEngine{}}}
	services := &stageServices{}
	if _, err := ApplyBootConfig(ctx, store, engine, services); err != nil {
		t.Fatal(err)
	}
	if engine.mutations != 0 || services.mutations != 0 || !engine.dp.Enforcement ||
		len(engine.dp.CaptureInterfaces) != 0 || engine.dp.DPIEnabled ||
		engine.snapshot.Default != rules.ActionDeny || len(engine.snapshot.Firewall) != 0 ||
		len(engine.snapshot.ZoneIfaces) != 0 || len(engine.snapshot.LocalInput) != 0 || engine.snapshot.NAT.Enabled {
		t.Fatalf("recovery leaked stored input: dp=%+v snap=%+v engine=%d services=%d", engine.dp, engine.snapshot, engine.mutations, services.mutations)
	}
	if err := config.ValidateManagementDataPlane(engine.dp, config.ReservationForStore(store)); err != nil {
		t.Fatal(err)
	}
	compiler := enforce.NewCompiler()
	compiler.ManagementReservation = config.ReservationForStore(store)
	compiled, err := compiler.CompileFirewall(&engine.snapshot)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(compiled, "policy drop") || !strings.Contains(compiled, "10.99.99.10") {
		t.Fatalf("recovery missing deny/reserved rule: %s", compiled)
	}
	// In split mode the engine also admits its non-loopback API path, which
	// management cannot know: the engine's ruleset differs from any
	// management compile, yet it is the recovery ruleset.
	engineSide := enforce.NewCompiler()
	engineSide.ManagementReservation = config.ReservationForStore(store)
	engineSide.EngineAPI = &enforce.EngineAPIPath{Device: "eth6", Addr: netip.MustParseAddr("192.0.2.10"), Port: 8081}
	split, err := engineSide.CompileFirewall(&engine.snapshot)
	if err != nil {
		t.Fatal(err)
	}
	if split == compiled {
		t.Fatal("engine API path did not change the compiled ruleset")
	}
	recovery := config.ManagementRecoveryVersion
	for _, tc := range []struct {
		name   string
		status dpengine.RulesetStatus
		want   string
	}{
		{"not applied", dpengine.RulesetStatus{}, "recovery pending:"},
		{"apply failed", dpengine.RulesetStatus{FailedSnapshotVersion: recovery, Error: "nft failed"}, "recovery failed:"},
		{"apply failed over another snapshot", dpengine.RulesetStatus{Ruleset: compiled, SnapshotVersion: "compiled-0.1.7", AppliedAt: time.Now(), FailedSnapshotVersion: recovery, Error: "nft failed"}, "recovery failed:"},
		{"applied, a later apply failed", dpengine.RulesetStatus{Ruleset: compiled, SnapshotVersion: recovery, AppliedAt: time.Now(), FailedSnapshotVersion: recovery, Error: "nft failed"}, "recovery: new transit dropped"},
		{"other snapshot applied", dpengine.RulesetStatus{Ruleset: compiled, SnapshotVersion: "compiled-0.1.7", AppliedAt: time.Now()}, "recovery pending:"},
		{"version unreported", dpengine.RulesetStatus{Ruleset: compiled, AppliedAt: time.Now()}, "recovery pending:"},
		{"no ruleset", dpengine.RulesetStatus{SnapshotVersion: recovery, AppliedAt: time.Now()}, "recovery pending:"},
		{"never applied", dpengine.RulesetStatus{Ruleset: compiled, SnapshotVersion: recovery}, "recovery pending:"},
		{"applied", dpengine.RulesetStatus{Ruleset: compiled, SnapshotVersion: recovery, AppliedAt: time.Now()}, "recovery: new transit dropped"},
		{"applied with an engine API path", dpengine.RulesetStatus{Ruleset: split, SnapshotVersion: recovery, AppliedAt: time.Now()}, "recovery: new transit dropped"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			engine.ruleset = tc.status
			got := managementRecoveryStatus(ctx, engine)
			if !strings.HasPrefix(got, tc.want) {
				t.Fatalf("status = %q", got)
			}
			server := NewServerWithEngineAndServices(store, nil, engine, nil, nil, ManagementListenerFaults(func() []string { return []string{"https bind failed"} }))
			rec := requestStage(t, server, "GET", "/system/management-reservation", nil)
			if !strings.Contains(rec.Body.String(), tc.want) || !strings.Contains(rec.Body.String(), "https bind failed") {
				t.Fatalf("fault/status not exposed: %s", rec.Body)
			}
		})
	}
	// Failure cannot become a warning/success, even for an nft permission error.
	engine.rulesErr = errors.New("nft apply failed: permission denied")
	if _, err := ApplyBootConfig(ctx, store, engine, services); err == nil {
		t.Fatal("recovery apply failure ignored")
	}
	engine.rulesErr = nil
	engine.configErr = errors.New("configure failed")
	if _, err := ApplyBootConfig(ctx, store, engine, services); err == nil {
		t.Fatal("recovery configure failure ignored")
	}
	engine.configErr = nil
	if err := store.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := ApplyBootConfig(ctx, store, engine, services); err != nil {
		t.Fatal(err)
	}
	if engine.mutations == 0 || services.mutations == 0 {
		t.Fatal("safe commit did not restore normal apply")
	}
}

func TestQueuedRecoveryRechecksPromotionUnderApplyLock(t *testing.T) {
	store, _ := reservedAPIStore(t)
	ctx := context.Background()
	if err := store.SetManagementBootFault(ctx, "stored conflict"); err != nil {
		t.Fatal(err)
	}
	engine := &recoveryEngine{stageEngine: &stageEngine{mockEngine: &mockEngine{}}}
	services := &stageServices{}
	runningConfigApplyMu.Lock()
	done := make(chan error, 1)
	go func() {
		_, err := ApplyBootConfig(ctx, store, engine, services)
		done <- err
	}()
	err := store.Commit(ctx)
	runningConfigApplyMu.Unlock()
	if err != nil {
		t.Fatal(err)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if engine.snapshot.Version == config.ManagementRecoveryVersion || engine.mutations == 0 || services.mutations == 0 {
		t.Fatal("queued recovery overwrote a safe promotion")
	}
}

func TestManagementRecoveryWithoutReservation(t *testing.T) {
	ctx := context.Background()
	store, err := config.NewSQLiteStore(filepath.Join(t.TempDir(), "config.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { store.Close() })
	f := false
	cfg := config.DefaultConfig()
	cfg.Interfaces = []config.Interface{
		{Name: "mgmt0", Device: "mgmtnic", Zone: "mgmt"},
		{Name: "wan0", Device: "wannic", Zone: "wan", Access: config.InterfaceAccess{Mgmt: &f}},
	}
	cfg.DataPlane.Enforcement = true
	if err := store.Save(ctx, cfg); err != nil {
		t.Fatal(err)
	}
	const fault = "rule modbus-enforce: modbus enforce needs an inline path"
	if err := store.SetManagementBootFault(ctx, fault); err != nil {
		t.Fatal(err)
	}
	engine := &recoveryEngine{stageEngine: &stageEngine{mockEngine: &mockEngine{}}}
	services := &stageServices{}
	if _, err := ApplyBootConfig(ctx, store, engine, services); err != nil {
		t.Fatal(err)
	}
	snap := engine.snapshot
	if engine.mutations != 0 || services.mutations != 0 || !engine.dp.Enforcement ||
		snap.Version != config.ManagementRecoveryVersion || snap.Default != rules.ActionDeny ||
		len(snap.Firewall) != 0 || len(snap.ZoneIfaces) != 0 || snap.NAT.Enabled {
		t.Fatalf("recovery leaked stored input: dp=%+v snap=%+v engine=%d services=%d", engine.dp, snap, engine.mutations, services.mutations)
	}
	// Without a reservation, stored management access is the only way in:
	// the stored listeners, HTTPS included, which the stored config leaves
	// to its default.
	stored := compile.ManagementLocalInput(cfg)
	if !reflect.DeepEqual(snap.LocalInput, stored) || !slices.ContainsFunc(stored, func(r rules.LocalServiceRule) bool {
		return r.ID == "auto-allow-mgmt-https" && r.Port == 8443
	}) {
		t.Fatalf("recovery management input = %+v", snap.LocalInput)
	}

	type healthBody struct {
		Enforcement struct{ State string } `json:"enforcement"`
		Recovery    struct {
			State  string `json:"state"`
			Reason string `json:"reason"`
		} `json:"managementRecovery"`
	}
	server := NewServerWithEngineAndServices(store, nil, engine, nil, nil)
	health := func() healthBody {
		t.Helper()
		rec := httptest.NewRecorder()
		server.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/v1/health", nil))
		var body healthBody
		if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
			t.Fatal(err)
		}
		if strings.Contains(rec.Body.String(), "modbus-enforce") {
			t.Fatalf("unauthenticated health names stored rules: %s", rec.Body)
		}
		return body
	}
	for _, tc := range []struct {
		name   string
		status dpengine.RulesetStatus
		state  string
		view   string
	}{
		{"pending", dpengine.RulesetStatus{}, "pending", "recovery pending:"},
		{"failed", dpengine.RulesetStatus{FailedSnapshotVersion: config.ManagementRecoveryVersion, Error: "nft failed"}, "failed", "recovery failed: nft failed"},
		{"applied", dpengine.RulesetStatus{Ruleset: "x", SnapshotVersion: config.ManagementRecoveryVersion, AppliedAt: time.Now()}, "active", "recovery: new transit dropped"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			engine.ruleset = tc.status
			body := health()
			if body.Recovery.State != tc.state || !strings.Contains(body.Recovery.Reason, "refused at boot") || body.Enforcement.State != "unavailable" {
				t.Fatalf("health = %+v", body)
			}
			rec := requestStage(t, server, "GET", "/system/management-reservation", nil)
			var view map[string]any
			if err := json.Unmarshal(rec.Body.Bytes(), &view); err != nil {
				t.Fatal(err)
			}
			if view["active"] != false || view["bootFault"] != fault || !strings.HasPrefix(view["recovery"].(string), tc.view) {
				t.Fatalf("reservation view = %s", rec.Body)
			}
		})
	}

	if err := store.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	engine.ruleset = dpengine.RulesetStatus{Ruleset: "x", SnapshotVersion: "compiled", AppliedAt: time.Now()}
	if body := health(); body.Recovery.State != "inactive" || body.Recovery.Reason != "" || body.Enforcement.State != "enforcing" {
		t.Fatalf("health after commit = %+v", body)
	}
	if rec := requestStage(t, server, "GET", "/system/management-reservation", nil); strings.TrimSpace(rec.Body.String()) != `{"active":false}` {
		t.Fatalf("reservation view after commit = %s", rec.Body)
	}
}

// Without a reservation, recovery admits management on the stored
// listeners and on the listeners management has bound, the appliance
// defaults after a listener fallback, both only where stored access grants
// management.
func TestRecoverySnapshotAdmitsBoundListeners(t *testing.T) {
	f := false
	stored := config.DefaultConfig()
	stored.System.Mgmt.HTTPListenAddr = "192.0.2.50:9090"
	stored.Interfaces = []config.Interface{
		{Name: "mgmt0", Device: "mgmtnic", Zone: "mgmt"},
		{Name: "wan0", Device: "wannic", Zone: "wan", Access: config.InterfaceAccess{Mgmt: &f}},
	}
	httpPorts := func() map[int]rules.LocalServiceRule {
		ports := map[int]rules.LocalServiceRule{}
		for _, rule := range RecoverySnapshot(stored, nil).LocalInput {
			if strings.HasPrefix(rule.ID, "auto-allow-mgmt-http") && !strings.HasPrefix(rule.ID, "auto-allow-mgmt-https") {
				ports[rule.Port] = rule
			}
		}
		return ports
	}
	if ports := httpPorts(); len(ports) != 1 || ports[9090].ID != "auto-allow-mgmt-http" {
		t.Fatalf("recovery HTTP management input before any bind = %+v", ports)
	}
	config.SetBoundManagementListeners(config.EffectiveManagementListeners(WithApplianceListeners(stored, nil)))
	t.Cleanup(func() { config.SetBoundManagementListeners(config.ManagementListeners{}) })
	ports := httpPorts()
	for port, id := range map[int]string{9090: "auto-allow-mgmt-http", 8080: "auto-allow-mgmt-http-bound"} {
		rule, ok := ports[port]
		if !ok || rule.ID != id || !reflect.DeepEqual(rule.Ifaces, []string{"mgmtnic"}) || !reflect.DeepEqual(rule.DeniedIfaces, []string{"wannic"}) {
			t.Fatalf("recovery HTTP management input on %d = %+v (%v)", port, rule, ok)
		}
	}
	if len(ports) != 2 {
		t.Fatalf("recovery HTTP management input = %+v", ports)
	}
}
