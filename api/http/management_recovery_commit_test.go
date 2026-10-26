// SPDX-License-Identifier: Apache-2.0
package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"path/filepath"
	"testing"

	"github.com/tonylturner/containd/pkg/cp/config"
	"github.com/tonylturner/containd/pkg/dp/rules"
)

// commitFailingEngine applies only the recovery ruleset; every other
// ruleset fails, as a commit that fails at runtime does.
type commitFailingEngine struct {
	*recoveryEngine
	applied []string
}

func (e *commitFailingEngine) ApplyRules(ctx context.Context, snapshot rules.Snapshot) error {
	e.applied = append(e.applied, snapshot.Version)
	if err := e.recoveryEngine.ApplyRules(ctx, snapshot); err != nil {
		return err
	}
	if snapshot.Version != config.ManagementRecoveryVersion {
		return errors.New("nft apply failed")
	}
	return nil
}

// A transition that fails at runtime while the appliance is in management
// recovery restores the refused running configuration, which must never be
// reapplied: the engine gets the recovery ruleset again and the boot fault
// stays.
func TestFailedTransitionDuringRecoveryReentersRecovery(t *testing.T) {
	ctx := context.Background()
	store, err := config.NewSQLiteStore(filepath.Join(t.TempDir(), "config.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { store.Close() })
	cfg := config.DefaultConfig()
	cfg.Interfaces = []config.Interface{{Name: "mgmt0", Device: "mgmtnic", Zone: "mgmt"}}
	cfg.DataPlane.Enforcement = true
	if err := store.Save(ctx, cfg); err != nil {
		t.Fatal(err)
	}
	const fault = "rule modbus-enforce: modbus enforce needs an inline path"
	if err := store.SetManagementBootFault(ctx, fault); err != nil {
		t.Fatal(err)
	}
	engine := &commitFailingEngine{recoveryEngine: &recoveryEngine{stageEngine: &stageEngine{mockEngine: &mockEngine{}}}}
	if _, err := ApplyBootConfig(ctx, store, engine, &stageServices{}); err != nil {
		t.Fatal(err)
	}
	server := NewServerWithEngineAndServices(store, nil, engine, &stageServices{}, nil)

	for _, path := range []string{"/config/commit", "/config/commit_confirmed"} {
		t.Run(path, func(t *testing.T) {
			if err := store.SaveCandidate(ctx, cfg); err != nil {
				t.Fatal(err)
			}
			engine.applied = nil
			rec := requestStage(t, server, "POST", path, nil)
			var body map[string]any
			if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
				t.Fatal(err)
			}
			if rec.Code != http.StatusInternalServerError || body["restored"] != true || body["reapplied"] != true {
				t.Fatalf("commit = %d %s", rec.Code, rec.Body)
			}
			if n := len(engine.applied); n < 2 || engine.applied[n-1] != config.ManagementRecoveryVersion {
				t.Fatalf("applied rulesets %q, want the recovery ruleset last", engine.applied)
			}
			for _, version := range engine.applied[1:] {
				if version != config.ManagementRecoveryVersion {
					t.Fatalf("applied rulesets %q: the refused configuration was reapplied", engine.applied)
				}
			}
			if !engine.dp.Enforcement || engine.dp.DPIEnabled || len(engine.dp.CaptureInterfaces) != 0 {
				t.Fatalf("dataplane after the failed commit = %+v, want recovery's", engine.dp)
			}
			if got, err := store.ManagementBootFault(ctx); err != nil || got != fault {
				t.Fatalf("boot fault = %q, %v", got, err)
			}
			if got, err := store.RuntimeApplyFault(ctx); err != nil || got != "" {
				t.Fatalf("runtime apply fault = %q, %v", got, err)
			}
		})
	}

	// A failed recovery apply is the compensation's failure.
	engine.rulesErr = errors.New("nft unavailable")
	if err := store.SaveCandidate(ctx, cfg); err != nil {
		t.Fatal(err)
	}
	rec := requestStage(t, server, "POST", "/config/commit", nil)
	var body map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if rec.Code != http.StatusInternalServerError || body["reapplied"] != false {
		t.Fatalf("commit with a failing recovery = %d %s", rec.Code, rec.Body)
	}
	if got, err := store.RuntimeApplyFault(ctx); err != nil || got == "" {
		t.Fatalf("runtime apply fault = %q, %v; a failed recovery must be recorded", got, err)
	}
}
