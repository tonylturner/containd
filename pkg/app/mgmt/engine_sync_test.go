// SPDX-License-Identifier: Apache-2.0
package mgmtapp

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync"
	"testing"

	engineapi "github.com/tonylturner/containd/api/engine"
	httpapi "github.com/tonylturner/containd/api/http"
	"github.com/tonylturner/containd/pkg/app/convergence"
	"github.com/tonylturner/containd/pkg/cp/config"
	"github.com/tonylturner/containd/pkg/cp/services"
	"go.uber.org/zap"
)

func mgmtTestCoordinator(t *testing.T, store config.Store, engine httpapi.EngineClient, manager *services.Manager) convergence.Coordinator {
	t.Helper()
	if manager == nil {
		manager = services.NewManager(services.ManagerOptions{BaseDir: t.TempDir()})
	}
	env := &httpapi.RuntimeEnvironment{Store: store, Engine: engine, RefreshMaterial: func(ctx context.Context, s *config.RunningSnapshot) error {
		return httpapi.RefreshLocalMaterial(ctx, store, manager, s)
	}}
	c, err := convergence.New(convergence.Options{Store: store.(config.RuntimeStore), Engine: engine, Services: manager, Environment: env})
	if err != nil {
		t.Fatal(err)
	}
	return c
}

// Existing boot fixtures now drive the real coordinator, not a replay loop.
func startTestConvergence(t *testing.T, ctx context.Context, store config.Store, engine httpapi.EngineClient) func() {
	c := mgmtTestCoordinator(t, store, engine, nil)
	stop := startConvergence(ctx, c, zap.NewNop().Sugar(), nil)
	var once sync.Once
	return func() {
		once.Do(func() {
			if err := stop(); err != nil {
				t.Error(err)
			}
		})
	}
}

func TestUnreachableEngineBootstrapsLocalOwnersWithoutRemoteProof(t *testing.T) {
	ctx := context.Background()
	store, err := config.NewSQLiteStore(filepath.Join(t.TempDir(), "config.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	cfg := config.DefaultConfig()
	cfg.Interfaces = nil
	cfg.Services.DNS.Enabled = true
	if err := store.Save(ctx, cfg); err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "unreachable", http.StatusServiceUnavailable)
	}))
	defer server.Close()
	manager := services.NewManager(services.ManagerOptions{BaseDir: t.TempDir()})
	manager.Proxy, manager.VPN, manager.NTP, manager.DHCP, manager.Syslog = nil, nil, nil, nil, nil
	binary := filepath.Join(t.TempDir(), "unbound")
	if err := os.WriteFile(binary, []byte("#!/bin/sh\nexec sleep 600\n"), 0700); err != nil {
		t.Fatal(err)
	}
	manager.DNS.Supervise, manager.DNS.UnboundPath = true, binary
	manager.DNS.CheckConfPath, manager.DNS.ControlPath = "", ""
	t.Cleanup(func() {
		if err := manager.DNS.Apply(ctx, config.DNSConfig{}); err != nil {
			t.Error(err)
		}
	})
	engine := engineapi.NewHTTPClient(server.URL)
	if err := bootstrapLocalServices(ctx, store, engine, manager); err != nil {
		t.Fatal(err)
	}
	if !manager.DNS.Current().Enabled || manager.DNS.Status()["running"] != true {
		t.Fatal("local DNS not started")
	}
	if b, err := os.ReadFile(filepath.Join(manager.DNS.BaseDir, "unbound.conf")); err != nil || len(b) == 0 {
		t.Fatalf("local owner did not render: %v", err)
	}
	if outcomes := manager.DeliveryOutcomes(); len(outcomes) != 0 {
		t.Fatalf("bootstrap minted remote proof: %+v", outcomes)
	}
	coordinator := mgmtTestCoordinator(t, store, engine, manager)
	status, err := coordinator.Status(ctx)
	if err == nil || status.Ready || status.ProtectingRevision != nil {
		t.Fatalf("unreachable engine ready: %+v %v", status, err)
	}
	if err := coordinator.Tick(ctx); err == nil {
		t.Fatal("unreachable engine accepted delivery")
	}
}

type drainCoordinator struct {
	convergence.Coordinator
	entered chan struct{}
}

func (c *drainCoordinator) Run(ctx context.Context) error {
	close(c.entered)
	<-ctx.Done()
	return convergence.ErrDrain
}
func TestConvergenceStopPreservesDrainError(t *testing.T) {
	c := &drainCoordinator{entered: make(chan struct{})}
	stop := startConvergence(context.Background(), c, zap.NewNop().Sugar(), nil)
	<-c.entered
	if err := stop(); !errors.Is(err, convergence.ErrDrain) {
		t.Fatalf("lost unsafe store-close guard: %v", err)
	}
}
