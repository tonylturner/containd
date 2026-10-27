// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

package engineapp

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"reflect"
	"sync"

	"go.uber.org/zap"

	"github.com/tonylturner/containd/pkg/common/mgmtpath"
	"github.com/tonylturner/containd/pkg/cp/config"
	"github.com/tonylturner/containd/pkg/dp/capture"
	"github.com/tonylturner/containd/pkg/dp/enforce"
	"github.com/tonylturner/containd/pkg/dp/engine"
	"github.com/tonylturner/containd/pkg/dp/events"
)

// dataPlane is what the config handler drives. *engine.Engine implements it.
type dataPlane interface {
	ManagementReservation() *mgmtpath.Reservation
	Events() *events.Store
	SetICSParsing(map[string]string)
	Reconfigure(fresh *engine.Engine) error
	StartWithRetry(ctx context.Context) error
}

// appliedConfig is the data-plane configuration the engine runs. The zero
// value has applied=false: the engine was built from the process defaults,
// so the first POST always rebuilds.
type appliedConfig struct {
	mu      sync.Mutex
	applied bool
	dp      config.DataPlaneConfig
}

func (a *appliedConfig) get() config.DataPlaneConfig {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.dp
}

// configHandler applies a data-plane configuration. A configuration equal to
// the applied one does not rebuild the engine: its events, inventory,
// sessions and NFQUEUE binding survive, and the DPI mock simulation keeps
// running. Parsing-only changes atomically update policy without retiring
// sessions. It still asks the engine to start, which is a no-op while it runs
// and retries the queue bind after an earlier attempt gave up. A changed
// configuration rebuilds the engine as before. A rebuild that cannot take
// effect (the nft tables of a disabled enforcement cannot be removed) fails
// the POST and leaves the applied configuration unchanged, so a retry
// rebuilds again.
func configHandler(logger *zap.SugaredLogger, dp dataPlane, simMgr *simulationManager) http.HandlerFunc {
	store := dp.Events()
	var current appliedConfig
	var post sync.Mutex // one POST at a time: compare, rebuild and record together
	return func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			writeJSON(w, current.get())
		case http.MethodPost:
			body, err := io.ReadAll(r.Body)
			if err != nil {
				http.Error(w, "failed to read body", http.StatusBadRequest)
				return
			}
			var next config.DataPlaneConfig
			if err := json.Unmarshal(body, &next); err != nil {
				http.Error(w, "invalid JSON: "+err.Error(), http.StatusBadRequest)
				return
			}
			if err := config.ValidateDataPlaneConfig(next); err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			if err := config.ValidateManagementDataPlane(next, dp.ManagementReservation()); err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			post.Lock()
			defer post.Unlock()
			current.mu.Lock()
			unchanged := current.applied && sameDataPlane(current.dp, next)
			previous := current.dp
			previous.DPIICSParsing = next.DPIICSParsing
			parsingOnly := current.applied && sameDataPlane(previous, next)
			current.mu.Unlock()
			if !unchanged && parsingOnly {
				dp.SetICSParsing(next.DPIICSParsing)
				current.mu.Lock()
				current.dp = next
				current.mu.Unlock()
			}
			if !unchanged && !parsingOnly {
				fresh, err := newEngineFor(logger, next, store, dp.ManagementReservation())
				if err != nil {
					http.Error(w, err.Error(), http.StatusBadRequest)
					return
				}
				if err := dp.Reconfigure(fresh); err != nil {
					http.Error(w, err.Error(), http.StatusInternalServerError)
					return
				}
				current.mu.Lock()
				current.applied, current.dp = true, next
				current.mu.Unlock()
				simMgr.stop()
				if next.DPIMock {
					simMgr.start(nil)
				}
			}
			go func() {
				if err := dp.StartWithRetry(context.Background()); err != nil {
					logger.Errorf("capture start failed: %v", err)
				}
			}()
			writeJSON(w, map[string]any{"status": "configured", "unchanged": unchanged})
		default:
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		}
	}
}

// sameDataPlane reports whether two configurations are identical in every
// field. Lists compare element by element in order; a nil and an empty list
// or map differ, so the comparison errs towards a rebuild.
func sameDataPlane(a, b config.DataPlaneConfig) bool {
	return reflect.DeepEqual(a, b)
}

// newEngineFor builds an engine for a data-plane configuration.
func newEngineFor(logger *zap.SugaredLogger, dp config.DataPlaneConfig, store *events.Store, reservation *mgmtpath.Reservation) (*engine.Engine, error) {
	var excl []engine.DPIExclusion
	for _, e := range dp.DPIExclusions {
		excl = append(excl, engine.DPIExclusion{Value: e.Value, Type: e.Type})
	}
	settings := compilerSettings(dp)
	table := settings.TableName
	return engine.New(engine.Config{
		Capture: capture.Config{Interfaces: dp.CaptureInterfaces},
		Events:  store,
		OnError: func(err error) {
			logger.Errorf("data plane capture error: %v", err)
		},
		Enforce: engine.EnforceConfig{ManagementReservation: reservation, Enabled: dp.Enforcement, TableName: table,
			GatePlainPort: settings.GatePlainPort, GateMasqPort: settings.GateMasqPort,
			Applier: enforce.NewNftApplier(), Updater: enforce.NewNftUpdater(table)},
		InspectAll:      dp.DPIMock,
		DPIEnabled:      dp.DPIEnabled,
		DPIMode:         dp.DPIMode,
		DPIProtocols:    dp.DPIProtocols,
		DPIICSProtocols: dp.DPIICSProtocols,
		DPIICSParsing:   dp.DPIICSParsing,
		DPIExclusions:   excl,
		NFLogGroup:      settings.NFLogGroup,
		NFQueueGroup:    settings.NFQueueGroup,
	})
}

// compilerSettings is the single candidate-config mapping for apply and
// preview. The scanning gate's listener ports are the defaults whenever
// enforcement is on.
func compilerSettings(dp config.DataPlaneConfig) enforce.CompilerSettings {
	s := enforce.CompilerSettings{
		TableName:  firstNonEmpty(dp.EnforceTable, "containd"),
		NFLogGroup: dp.NFLogGroup, NFQueueGroup: dp.NFQueueGroup,
	}
	if dp.Enforcement {
		s.GatePlainPort, s.GateMasqPort = enforce.DefaultGatePlainPort, enforce.DefaultGateMasqPort
	}
	return s
}
