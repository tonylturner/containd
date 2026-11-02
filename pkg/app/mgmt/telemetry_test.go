// SPDX-License-Identifier: Apache-2.0

package mgmtapp

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/tonylturner/containd/pkg/cp/services"
	"go.uber.org/zap"
)

func TestTelemetryWiringAndShutdown(t *testing.T) {
	t.Setenv("CONTAIND_TELEMETRY_DB", filepath.Join(t.TempDir(), "telemetry.db"))
	manager := services.NewManager(services.ManagerOptions{BaseDir: t.TempDir()})
	for range 2 {
		// Repeated start/stop uses the same wiring as both management modes.
		store, stop := startTelemetry(context.Background(), zap.NewNop().Sugar(), nil, manager)
		if store == nil {
			t.Fatal("history store not wired")
		}
		stop()
	}
}

func TestTelemetryUnavailableDoesNotBlockManagement(t *testing.T) {
	t.Setenv("CONTAIND_TELEMETRY_DB", t.TempDir()) // a directory, not a database
	store, stop := startTelemetry(context.Background(), zap.NewNop().Sugar(), nil, nil)
	defer stop()
	if store != nil {
		t.Fatal("expected unavailable telemetry, not failed management")
	}
}
