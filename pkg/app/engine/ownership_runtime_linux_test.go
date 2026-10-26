// SPDX-License-Identifier: Apache-2.0
//go:build linux

package engineapp

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/tonylturner/containd/pkg/cp/config"
	"go.uber.org/zap"
	"go.uber.org/zap/zaptest/observer"
)

func TestOwnershipWatchCancelsWithoutNetworkEvents(t *testing.T) {
	logs, observed := observer.New(zap.WarnLevel)
	manager := newOwnershipManager(zap.New(logs).Sugar())
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan struct{})
	go func() {
		defer close(done)
		manager.netlinkWatchLoop(ctx)
	}()
	// Let the watcher enter its receive wait. No network mutation is needed.
	time.Sleep(150 * time.Millisecond)
	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("ownership subscription leaked on cancellation")
	}
	if observed.Len() != 0 {
		t.Fatalf("watcher did not successfully subscribe: %v", observed.All())
	}
}

func TestOwnershipConcurrentStateUpdatesPreserveBothComponents(t *testing.T) {
	for range 100 {
		manager := newOwnershipManager(zap.NewNop().Sugar())
		var writers sync.WaitGroup
		writers.Go(func() { manager.setInterfaces([]config.Interface{{Name: "wan"}}) })
		writers.Go(func() { manager.setRouting(config.RoutingConfig{Rules: []config.PolicyRule{{Table: 201}}}) })
		writers.Wait()
		state := manager.state.Load().(ownershipState)
		if len(state.ifaces) != 1 || len(state.routing.Rules) != 1 {
			t.Fatalf("concurrent update lost a component: %+v", state)
		}
	}
}

func TestOwnershipEmptyRoutingIsKnownIntent(t *testing.T) {
	manager := newOwnershipManager(zap.NewNop().Sugar())
	if manager.state.Load().(ownershipState).routingSet {
		t.Fatal("startup must wait for routing intent")
	}
	manager.setInterfaces([]config.Interface{{Name: "plant"}})
	manager.setRouting(config.RoutingConfig{Rules: []config.PolicyRule{{Priority: 40000, Table: 201}}})
	manager.setRouting(config.RoutingConfig{})
	state := manager.state.Load().(ownershipState)
	if !state.routingSet || len(state.routing.Routes) != 0 || len(state.routing.Rules) != 0 || len(state.ifaces) != 1 {
		t.Fatalf("empty routing was lost: %+v", state)
	}
}
