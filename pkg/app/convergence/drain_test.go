// SPDX-License-Identifier: Apache-2.0

package convergence

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/tonylturner/containd/pkg/common/protection"
	"github.com/tonylturner/containd/pkg/cp/config"
)

func TestUncooperativeDrainRefusesOverlap(t *testing.T) {
	c, _, engine, _, _, _ := fixture(t)
	entered, release := make(chan struct{}), make(chan struct{})
	engine.hook = func(ctx context.Context, phase string) error {
		if phase == "interfaces" {
			close(entered)
			<-release
		}
		return ctx.Err()
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- c.Tick(ctx) }()
	<-entered
	drainCtx, drainCancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer drainCancel()
	_, err := c.Replay(drainCtx, false)
	if !errors.Is(err, ErrDrain) {
		t.Fatalf("overlap not refused: %v", err)
	}
	c.mu.Lock()
	in := c.current.input
	c.mu.Unlock()
	if !in.Uncertain || in.Coherent || len(in.Outcomes) == 0 {
		t.Fatal("drain uncertainty not exposed")
	}
	close(release)
	cancel()
	<-done
	// Cancellation may return Tick before the owner actually joined.
	if err := c.enter(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := c.drain(context.Background()); err != nil {
		t.Fatal(err)
	}
	c.leave()
}

func TestRunSafetyTimerCancelsActiveEffect(t *testing.T) {
	c, store, engine, _, _, _ := fixture(t)
	store.state.Running.PendingConfirm = &config.PendingConfirm{Deadline: time.Now().Add(150 * time.Millisecond)}
	entered, canceled := make(chan struct{}), make(chan struct{})
	var once sync.Once
	engine.hook = func(ctx context.Context, phase string) error {
		if phase == "nft" {
			once.Do(func() {
				close(entered)
				<-ctx.Done()
				close(canceled)
			})
			return ctx.Err()
		}
		return nil
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- c.Run(ctx) }()
	defer func() {
		cancel()
		if err := <-done; err != nil {
			t.Error(err)
		}
	}()
	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("baseline never reached owner")
	}
	select {
	case <-canceled:
	case <-time.After(time.Second):
		t.Fatal("deadline safety observer failed to cancel active work")
	}
	c.mu.Lock()
	coherent := c.current.input.Coherent
	c.mu.Unlock()
	if coherent {
		t.Fatal("expired epoch remained coherent")
	}
}

func TestLateFinalInstallCannotResurrectExpiry(t *testing.T) {
	c, _, engine, _, _, _ := fixture(t)
	entered, release := make(chan struct{}), make(chan struct{})
	engine.hook = func(ctx context.Context, phase string) error {
		if phase == "nft" {
			close(entered)
			<-ctx.Done()
			<-release
			return nil // transport completion arrives after expiry
		}
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- c.Tick(ctx) }()
	<-entered
	c.mu.Lock()
	c.current.deadline = time.Now().Add(-time.Second)
	c.mu.Unlock()
	c.expire()
	close(release)
	if err := <-done; !errors.Is(err, ErrSuperseded) && !errors.Is(err, context.Canceled) {
		t.Fatalf("expired completion accepted: %v", err)
	}
	c.mu.Lock()
	in := c.current.input
	c.mu.Unlock()
	in.Engine = protection.EngineObservation{Metadata: in.Current, State: protection.StateProtecting, ObservedAt: time.Now()}
	if protection.Reduce(in).Ready || in.Coherent {
		t.Fatal("late install resurrected old proof")
	}
}
