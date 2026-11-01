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
	"golang.org/x/sys/unix"
)

func TestOwnershipWatchCancelsWithoutNetworkEvents(t *testing.T) {
	logs, observed := observer.New(zap.WarnLevel)
	manager := newOwnershipManager(zap.New(logs).Sugar())
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan struct{})
	polling := make(chan struct{})
	var once sync.Once
	go func() {
		defer close(done)
		manager.netlinkWatchWith(ctx, func(fds []unix.PollFd, timeout int) (int, error) {
			once.Do(func() { close(polling) })
			return unix.Poll(fds, timeout)
		}, unix.Recvfrom)
	}()
	select {
	case <-polling:
	case <-done:
		t.Fatalf("watcher exited before polling: %v", observed.All())
	case <-time.After(time.Second):
		t.Fatal("watcher never entered poll")
	}
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

func TestOwnershipWatchRetriesEINTR(t *testing.T) {
	for _, interrupted := range []string{"poll", "recvfrom"} {
		t.Run(interrupted, func(t *testing.T) {
			logs, observed := observer.New(zap.WarnLevel)
			manager := newOwnershipManager(zap.New(logs).Sugar())
			ctx, cancel := context.WithCancel(context.Background())
			done := make(chan struct{})
			t.Cleanup(func() {
				cancel()
				select {
				case <-done:
				case <-time.After(time.Second):
					t.Error("ownership watcher leaked on cancellation")
				}
			})
			waiting := make(chan struct{})
			polls, receives := 0, 0
			delivered := false
			poll := func(fds []unix.PollFd, timeout int) (int, error) {
				polls++
				if len(fds) != 1 || fds[0].Events != unix.POLLIN || timeout != 100 {
					t.Errorf("unexpected poll request: %v timeout=%d", fds, timeout)
				}
				if interrupted == "poll" && polls == 1 {
					return 0, unix.EINTR
				}
				if delivered {
					close(waiting)
					<-ctx.Done()
					return 0, nil
				}
				return 1, nil
			}
			recvfrom := func(_ int, buf []byte, _ int) (int, unix.Sockaddr, error) {
				receives++
				if interrupted == "recvfrom" && receives == 1 {
					return 0, nil, unix.EINTR
				}
				buf[0] = 1
				delivered = true
				return 1, nil, nil
			}
			go func() {
				defer close(done)
				manager.netlinkWatchWith(ctx, poll, recvfrom)
			}()
			select {
			case <-manager.reconcileCh:
			case <-done:
				t.Fatalf("watcher exited after %s EINTR without reconciling: %v", interrupted, observed.All())
			case <-time.After(time.Second):
				t.Fatalf("no reconcile trigger after %s EINTR", interrupted)
			}
			select {
			case <-waiting:
			case <-time.After(time.Second):
				t.Fatal("watcher did not return to its cancellation-aware wait")
			}
			cancel()
			select {
			case <-done:
			case <-time.After(time.Second):
				t.Fatal("watcher did not exit after cancellation")
			}
			wantPolls, wantReceives := 3, 1
			if interrupted == "recvfrom" {
				wantReceives = 2
			}
			if polls != wantPolls || receives != wantReceives {
				t.Fatalf("syscalls poll=%d recvfrom=%d, want %d/%d", polls, receives, wantPolls, wantReceives)
			}
			if observed.Len() != 0 {
				t.Fatalf("EINTR was reported as a failure: %v", observed.All())
			}
		})
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
