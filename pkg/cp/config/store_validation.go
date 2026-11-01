// SPDX-License-Identifier: Apache-2.0
package config

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"time"

	"github.com/tonylturner/containd/pkg/common/mgmtpath"
)

type storeOptions struct {
	reservation *mgmtpath.Reservation
}

// StoreOption supplies immutable validation context before startup rollback.
type StoreOption func(*storeOptions)

// WithManagementReservation captures boot authority, never student config.
func WithManagementReservation(r *mgmtpath.Reservation) StoreOption {
	captured := copyReservation(r)
	return func(o *storeOptions) { o.reservation = captured }
}

func copyReservation(r *mgmtpath.Reservation) *mgmtpath.Reservation {
	if r == nil {
		return nil
	}
	cp := *r
	cp.Sources = append([]netip.Addr(nil), r.Sources...)
	return &cp
}

// ManagementReservation returns a detached operator view of startup authority.
func (s *SQLiteStore) ManagementReservation() *mgmtpath.Reservation {
	return copyReservation(s.options.reservation)
}

type ValidationError struct{ Err error }

func (e *ValidationError) Error() string { return e.Err.Error() }
func (e *ValidationError) Unwrap() error { return e.Err }

// ValidateConfig checks strict new content, including defaults and reset.
// Stored-state decisions use EffectiveForStore instead.
func (s *SQLiteStore) ValidateConfig(cfg *Config) error {
	if err := UpgradeInPlace(cfg); err != nil {
		return &ValidationError{err}
	}
	if err := CheckWrite(nil, cfg, s.options.reservation); err != nil {
		return &ValidationError{err}
	}
	return nil
}

// ValidateForStore shares the store's immutable context without expanding the
// Store interface implemented by non-SQLite consumers.
func ValidateForStore(store Store, cfg *Config) error {
	if validator, ok := store.(interface{ ValidateConfig(*Config) error }); ok {
		return validator.ValidateConfig(cfg)
	}
	if cfg == nil {
		return errors.New("config is nil")
	}
	return cfg.Validate()
}

const rollbackFaultKey = "management_reservation_rollback_fault"

// ManagementRollbackFault survives reopen, including a refused expiry at open.
func (s *SQLiteStore) ManagementRollbackFault(ctx context.Context) (string, error) {
	var fault string
	err := s.db.QueryRowContext(ctx, `SELECT data FROM configs WHERE key = ?`, rollbackFaultKey).Scan(&fault)
	if errors.Is(err, sql.ErrNoRows) {
		return "", nil
	}
	return fault, err
}

func (s *SQLiteStore) recordRollbackRefusal(ctx context.Context, err error) error {
	fault := fmt.Sprintf("%s: rollback refused: %v", time.Now().UTC().Format(time.RFC3339Nano), err)
	slog.Error("config.rollback.refused", "error", err)
	_, writeErr := s.db.ExecContext(ctx, `REPLACE INTO configs (key, data, updated_at) VALUES (?, ?, ?)`, rollbackFaultKey, fault, time.Now().Unix())
	return writeErr
}

func (s *SQLiteStore) timedRollbackLocked(ctx context.Context) (bool, error) {
	err := s.rollbackLocked(ctx)
	var invalid *ValidationError
	if errors.As(err, &invalid) {
		// Never retry an unsafe target. Keep running and the staged candidate;
		// retain previous for inspection, clear pending, and persist the fault.
		if clearErr := s.clearPendingLocked(ctx); clearErr != nil {
			return false, errors.Join(err, clearErr)
		}
		return false, nil
	}
	return err == nil, err
}

// ReservationForStore reads detached boot authority, never config data.
func ReservationForStore(store Store) *mgmtpath.Reservation {
	if authority, ok := store.(interface{ ManagementReservation() *mgmtpath.Reservation }); ok {
		return authority.ManagementReservation()
	}
	return nil
}

// EffectiveForStore shares immutable authority without acquiring the store lock.
func EffectiveForStore(store Store, cfg *Config) (*Config, []ServiceConfigError, error) {
	return Effective(cfg, ReservationForStore(store))
}

func (s *SQLiteStore) checkWrite(baseline, next *Config) error {
	if err := UpgradeInPlace(next); err != nil {
		return &ValidationError{err}
	}
	if err := CheckWrite(baseline, next, s.options.reservation); err != nil {
		return &ValidationError{err}
	}
	return nil
}
func (s *SQLiteStore) checkStored(cfg *Config) error {
	if _, _, err := Effective(cfg, s.options.reservation); err != nil {
		return &ValidationError{err}
	}
	return nil
}
