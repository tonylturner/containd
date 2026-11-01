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

// ValidateConfig is also used by API previews and replay preflight.
func (s *SQLiteStore) ValidateConfig(cfg *Config) error {
	if err := ValidateManagementReservation(cfg, s.options.reservation); err != nil {
		return &ValidationError{err}
	}
	if cfg == nil {
		return &ValidationError{errors.New("config is nil")}
	}
	if err := cfg.Validate(); err != nil {
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
	// Observe pending and its authority together; another handle may confirm or
	// supersede this deadline before the rollback acquires the write lock.
	tx, err := s.db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return false, err
	}
	defer tx.Rollback() //nolint:errcheck
	revision, err := readRevision(ctx, tx)
	if err != nil {
		return false, err
	}
	pending, err := loadPendingFrom(ctx, tx)
	if errors.Is(err, ErrNotFound) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if err := tx.Commit(); err != nil {
		return false, err
	}
	if remain := time.Until(time.Unix(0, pending.DeadlineUnix)); remain > 0 {
		s.schedulePendingLocked(remain)
		return false, nil
	}
	_, err = s.rollbackLocked(ctx, &revision, nil)
	var invalid *ValidationError
	if errors.As(err, &invalid) {
		// Clear only the pending generation whose rollback was refused.
		if clearErr := s.clearPendingLocked(ctx, revision); clearErr != nil {
			var mismatch *ErrRevisionMismatch
			if errors.As(clearErr, &mismatch) {
				s.schedulePendingLocked(time.Millisecond)
				return false, nil
			}
			return false, errors.Join(err, clearErr)
		}
		if recordErr := s.recordRollbackRefusal(ctx, err); recordErr != nil {
			return false, recordErr
		}
		return false, nil
	}
	var mismatch *ErrRevisionMismatch
	if errors.As(err, &mismatch) {
		s.schedulePendingLocked(time.Millisecond)
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
