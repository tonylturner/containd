// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

package mgmtapp

import (
	"context"
	"errors"
	"time"

	httpapi "github.com/tonylturner/containd/api/http"
	"github.com/tonylturner/containd/pkg/cp/config"
	"go.uber.org/zap"
)

const (
	engineSyncInterval      = time.Second
	engineSyncMaxBackoff    = 10 * time.Second
	engineSyncHealthTimeout = time.Second
)

type engineSync struct {
	store  config.Store
	health httpapi.RuntimeHealthClient
	apply  func(context.Context) ([]string, error)
	logger *zap.SugaredLogger
	replay <-chan struct{}

	applied    bool
	lastBootID string
	recovery   bool
	lastError  string
}

// startEngineSync returns a stop-and-join function so Run never closes its
// stores while a replay is still using them, including on listener errors.
func startEngineSync(ctx context.Context, logger *zap.SugaredLogger, store config.Store, engine httpapi.EngineClient, services httpapi.ServicesApplier) func() {
	health, ok := engine.(httpapi.RuntimeHealthClient)
	if !ok {
		return func() {}
	}
	ctx, cancel := context.WithCancel(ctx)
	syncer := &engineSync{
		store:  store,
		health: health,
		apply: func(ctx context.Context) ([]string, error) {
			return httpapi.ApplyBootConfig(ctx, store, engine, services)
		},
		logger: logger,
	}
	// Register before the first poll: an earlier expiry is covered by boot
	// replay; an expiry during that replay remains queued for another apply.
	// A channel, rather than a callback, guarantees the store never blocks or
	// calls back into itself while holding its mutex.
	replay := make(chan struct{}, 1)
	notifier, hasNotifier := store.(interface {
		SetAutoRollbackNotify(chan<- struct{})
	})
	if hasNotifier {
		notifier.SetAutoRollbackNotify(replay)
		syncer.replay = replay
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		syncer.run(ctx)
	}()
	return func() {
		if hasNotifier {
			notifier.SetAutoRollbackNotify(nil)
		}
		cancel()
		<-done
	}
}

func (s *engineSync) run(ctx context.Context) {
	delay := engineSyncInterval
	for ctx.Err() == nil {
		reachable := s.poll(ctx)
		if reachable {
			delay = engineSyncInterval
		}
		timer := time.NewTimer(delay)
		select {
		case <-ctx.Done():
			timer.Stop()
			return
		case <-timer.C:
		case <-s.replay:
			timer.Stop()
			// Retain the invalidation across health/apply failures so an
			// unchanged boot ID cannot suppress the retry.
			s.applied = false
		}
		if !reachable {
			delay = min(2*delay, engineSyncMaxBackoff)
		}
	}
}

// poll replays once per engine boot and mode transition. Failed attempts retry
// with capped backoff and log only changed errors, not a warning every tick.
func (s *engineSync) poll(ctx context.Context) bool {
	err := config.CheckManagementBootFault(ctx, s.store)
	recovery := errors.Is(err, config.ErrManagementBootFault)
	if err != nil && !recovery {
		s.logError(err)
		return false
	}
	if recovery != s.recovery {
		s.applied = false
		s.recovery = recovery
	}
	healthCtx, cancel := context.WithTimeout(ctx, engineSyncHealthTimeout)
	health, err := s.health.RuntimeHealth(healthCtx)
	cancel()
	if err != nil {
		// Older engines have no boot ID. Forget a successful unknown apply
		// only when health becomes unreachable, not on every poll.
		if s.lastBootID == "" {
			s.applied = false
		}
		s.logger.Debugf("engine sync health unavailable: %v", err)
		return false
	}
	if s.applied && health.BootID == s.lastBootID {
		return true
	}
	warnings, err := s.apply(ctx)
	for _, warning := range warnings {
		s.logger.Warnf("engine sync: %s", warning)
	}
	if err != nil {
		s.logError(err)
		return false
	}
	s.lastError = ""
	s.applied = true
	s.lastBootID = health.BootID
	s.logger.Infof("replayed config to engine (bootId=%q recovery=%v)", health.BootID, recovery)
	return true
}

func (s *engineSync) logError(err error) {
	if s.lastError != err.Error() {
		s.logger.Warnf("failed to replay config to engine: %v", err)
		s.lastError = err.Error()
	}
}
