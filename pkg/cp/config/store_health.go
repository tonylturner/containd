// SPDX-License-Identifier: Apache-2.0
package config

import (
	"context"
	"errors"
)

// HealthSnapshot is detached running metadata and its persisted apply fault.
// Config omits the separate IDS bank, which liveness does not need.
type HealthSnapshot struct {
	Config     *Config
	ApplyFault string
}

// HealthReader provides bounded observation without exposing an intermediate
// promotion or queuing liveness behind runtime apply/recovery.
type HealthReader interface {
	ReadHealthSnapshot(context.Context) (HealthSnapshot, error)
}

// ErrHealthBusy means a running-state operation is in progress. Health must
// report unknown rather than wait for it or observe an unapplied document.
var ErrHealthBusy = errors.New("configuration health snapshot busy")

func (s *SQLiteStore) ReadHealthSnapshot(ctx context.Context) (HealthSnapshot, error) {
	if err := ctx.Err(); err != nil {
		return HealthSnapshot{}, err
	}
	if !s.mu.TryLock() {
		return HealthSnapshot{}, ErrHealthBusy
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
