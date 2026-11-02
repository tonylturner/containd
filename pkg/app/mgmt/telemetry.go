// SPDX-License-Identifier: Apache-2.0

package mgmtapp

import (
	"context"
	"crypto/rand"
	"path/filepath"

	"github.com/tonylturner/containd/pkg/common"
	wire "github.com/tonylturner/containd/pkg/common/telemetry"
	"github.com/tonylturner/containd/pkg/cp/services"
	history "github.com/tonylturner/containd/pkg/cp/telemetry"
	"go.uber.org/zap"
)

// startTelemetry samples the engine (nil when management runs without one)
// and the management-local counters.
func startTelemetry(ctx context.Context, logger *zap.SugaredLogger, engine wire.CounterReader, services *services.Manager) (*history.Store, func()) {
	store, err := history.Open(common.Env("CONTAIND_TELEMETRY_DB", filepath.Join("data", "telemetry.db")))
	if err != nil {
		logger.Errorf("telemetry unavailable: %v", err)
		return nil, func() {}
	}
	sampler := history.NewSampler(store, engine, services.CounterReader(rand.Text()))
	ctx, cancel := context.WithCancel(ctx)
	done := make(chan struct{})
	go func() { defer close(done); sampler.Run(ctx) }()
	return store, func() {
		cancel()
		<-done
		if err := store.Close(); err != nil {
			logger.Warnf("close telemetry: %v", err)
		}
	}
}
