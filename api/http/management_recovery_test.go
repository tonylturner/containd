// SPDX-License-Identifier: Apache-2.0
package httpapi

import (
	"context"
	"errors"
	"net/netip"
	"strings"
	"testing"
	"time"

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
	recovery := RecoverySnapshot().Version
	for _, tc := range []struct {
		name   string
		status dpengine.RulesetStatus
		want   string
	}{
		{"not applied", dpengine.RulesetStatus{}, "recovery pending:"},
		{"apply failed", dpengine.RulesetStatus{Ruleset: compiled, SnapshotVersion: recovery, AppliedAt: time.Now(), Error: "nft failed"}, "recovery failed:"},
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
	if engine.snapshot.Version == RecoverySnapshot().Version || engine.mutations == 0 || services.mutations == 0 {
		t.Fatal("queued recovery overwrote a safe promotion")
	}
}
