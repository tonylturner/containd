// SPDX-License-Identifier: Apache-2.0
package httpapi

import (
	"context"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/tonylturner/containd/pkg/cp/audit"

	"github.com/tonylturner/containd/pkg/app/convergence"
	"github.com/tonylturner/containd/pkg/cp/config"
)

func testCoordinator(t *testing.T, store config.Store, engine EngineClient, services ServicesApplier) convergence.Coordinator {
	t.Helper()
	if services == nil {
		services = &stageServices{}
	}
	coordinator, err := convergence.New(convergence.Options{
		Store: store.(config.RuntimeStore), Engine: engine, Services: services,
		Environment: &RuntimeEnvironment{Store: store, Engine: engine},
	})
	if err != nil {
		t.Fatal(err)
	}
	return coordinator
}

// replayTestConfig drives the real coordinator, never the removed HTTP replay
// implementation. Tests which exercise supersession share testCoordinator.
func replayTestConfig(ctx context.Context, store config.Store, engine EngineClient, services ServicesApplier) ([]string, error) {
	if services == nil {
		services = &stageServices{}
	}
	coordinator, err := convergence.New(convergence.Options{
		Store: store.(config.RuntimeStore), Engine: engine, Services: services,
		Environment: &RuntimeEnvironment{Store: store, Engine: engine},
	})
	if err != nil {
		return nil, err
	}
	result, err := coordinator.Replay(ctx, false)
	return deliveryWarnings(ctx, coordinator, result.Warnings), err
}

func testRunningRevision(store config.RuntimeStore) config.RunningRevision {
	state, err := store.ReadRunning(context.Background())
	if err != nil {
		panic(err)
	}
	return state.Running.RunningRevision
}

func testRuntimeHandler(t *testing.T, store config.Store, engine EngineClient, services ServicesApplier, handler gin.HandlerFunc) gin.HandlerFunc {
	t.Helper()
	var runtimeEngine convergence.EngineClient = engine
	if runtimeEngine == nil {
		runtimeEngine = unavailableEngine{}
	}
	if services == nil {
		services = &stageServices{}
	}
	coordinator, err := convergence.New(convergence.Options{Store: store.(config.RuntimeStore), Engine: runtimeEngine, Services: services, Environment: &RuntimeEnvironment{Store: store, Engine: engine}})
	if err != nil {
		t.Fatal(err)
	}
	return func(c *gin.Context) { c.Set(runtimeContextKey, coordinator); handler(c) }
}
func newTestServerWithEngine(store config.Store, auditStore audit.Store, engine EngineClient) *gin.Engine {
	return NewServerWithEngineAndServices(store, auditStore, engine, &stageServices{}, nil)
}
