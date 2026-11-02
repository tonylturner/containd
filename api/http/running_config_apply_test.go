// SPDX-License-Identifier: Apache-2.0
package httpapi

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"github.com/tonylturner/containd/pkg/common/protection"
	"github.com/tonylturner/containd/pkg/cp/config"
	"github.com/tonylturner/containd/pkg/dp/rules"
)

type blockingApplyEngine struct {
	*mockEngine
	entered chan struct{}
	joined  atomic.Bool
	calls   atomic.Int32
}

func (e *blockingApplyEngine) ApplyRules(ctx context.Context, _ protection.Admission, snap rules.Snapshot) error {
	if e.calls.Add(1) == 1 {
		close(e.entered)
		<-ctx.Done()
		e.joined.Store(true)
		return ctx.Err()
	}
	if !e.joined.Load() {
		return errors.New("overlapping owner effects")
	}
	e.snap = snap
	return nil
}

func TestConvergenceJoinsOldDeliveryBeforeRunningMutation(t *testing.T) {
	for _, change := range []config.RunningChange{config.ChangeCommit, config.ChangeCommitConfirmed, config.ChangeRollback} {
		t.Run(string(change), func(t *testing.T) {
			store := stageStore(t)
			if err := testCommit(store, context.Background()); err != nil {
				t.Fatal(err)
			}
			candidate, err := store.Load(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			candidate.Firewall.DefaultAction = config.ActionDeny
			if err := testSaveCandidate(store, context.Background(), candidate); err != nil {
				t.Fatal(err)
			}
			engine := &blockingApplyEngine{mockEngine: &mockEngine{}, entered: make(chan struct{})}
			coordinator := testCoordinator(t, store, engine, &stageServices{})
			tick := make(chan error, 1)
			go func() { tick <- coordinator.Tick(context.Background()) }()
			select {
			case <-engine.entered:
			case <-time.After(3 * time.Second):
				t.Fatal("delivery not entered")
			}
			result, err := coordinator.Change(context.Background(), testBaseRevision(store, context.Background()), change, time.Minute)
			if err != nil {
				t.Fatal(err)
			}
			if err := <-tick; !errors.Is(err, context.Canceled) {
				t.Fatalf("old worker=%v", err)
			}
			state, err := store.ReadRunning(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			if !engine.joined.Load() || result.RunningRevision != state.Running.RunningRevision || engine.calls.Load() != 2 {
				t.Fatalf("old delivery escaped fence: %+v", result)
			}
		})
	}
}
