// SPDX-License-Identifier: Apache-2.0
package config

import (
	"context"
	"errors"
	"time"
)

// HealthSnapshot is detached running metadata and its persisted apply fault.
// Config omits the separate IDS bank, which liveness does not need.
type HealthSnapshot struct {
	Config     *Config
	ApplyFault string
}

// HealthReader provides observation within the caller's shared budget without
// exposing an intermediate promotion.
type HealthReader interface {
	ReadHealthSnapshot(context.Context) (HealthSnapshot, error)
}

// ErrHealthBusy means the store stayed busy until the observation budget ended.
// Health must report unknown rather than observe an unapplied document.
var ErrHealthBusy = errors.New("configuration health snapshot busy")

func (s *SQLiteStore) ReadHealthSnapshot(ctx context.Context) (HealthSnapshot, error) {
	if err := ctx.Err(); err != nil {
		return HealthSnapshot{}, err
	}
	if !s.mu.TryLock() {
		// Brief reads and candidate writes share this mutex with runtime apply.
		// Allow those to finish without extending the caller's shared budget.
		retry := time.NewTicker(2 * time.Millisecond)
		defer retry.Stop()
		for {
			select {
			case <-ctx.Done():
				return HealthSnapshot{}, errors.Join(ErrHealthBusy, ctx.Err())
			case <-retry.C:
			}
			if err := ctx.Err(); err != nil {
				return HealthSnapshot{}, errors.Join(ErrHealthBusy, err)
			}
			if s.mu.TryLock() {
				break
			}
		}
	}
	defer s.mu.Unlock()
	cfg, err := s.loadKind(ctx, configKeyRunning)
	if err != nil && !errors.Is(err, ErrNotFound) {
		return HealthSnapshot{}, err
	}
	fault, err := s.runtimeApplyFaultLocked(ctx)
	if err != nil {
		return HealthSnapshot{}, err
	}
	if err := ctx.Err(); err != nil {
		return HealthSnapshot{}, err
	}
	return HealthSnapshot{Config: cfg, ApplyFault: fault}, nil
}
