// SPDX-License-Identifier: Apache-2.0
package mgmtapp

import (
	"context"

	httpapi "github.com/tonylturner/containd/api/http"
	"github.com/tonylturner/containd/pkg/cp/config"
	"github.com/tonylturner/containd/pkg/cp/services"
)

// Bootstrap uses the same local owners without attaching a remote boot proof.
// When engine contact becomes possible, ApplyDelivery must independently
// confirm/adopt or safely reconcile these owners into the admitted attempt.
func bootstrapLocalServices(ctx context.Context, store config.Store, engine httpapi.EngineClient, manager *services.Manager) error {
	if health, ok := engine.(httpapi.RuntimeHealthClient); ok {
		probe, cancel := context.WithTimeout(ctx, engineSyncHealthTimeout)
		_, err := health.RuntimeHealth(probe)
		cancel()
		if err == nil {
			return nil
		}
	}
	if err := config.CheckManagementBootFault(ctx, store); err != nil {
		return err
	}
	state, err := store.(config.RuntimeStore).ReadRunning(ctx)
	if err != nil {
		return err
	}
	if state.Running == nil {
		return config.ErrNotFound
	}
	if state.Transition != nil && state.Transition.State != config.TransitionReapplyPending {
		// An unresolved transition cannot authorize ordinary service effects.
		return nil
	}
	_, faults, err := config.EffectiveForStore(store, state.Running.Config)
	if err != nil {
		return err
	}
	manager.SeedFaults(faults)
	return httpapi.RefreshLocalMaterial(ctx, store, manager, state.Running)
}
