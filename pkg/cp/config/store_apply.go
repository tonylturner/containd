// SPDX-License-Identifier: Apache-2.0
package config

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"
)

// RunningChange identifies a running-state transition coupled to runtime apply.
type RunningChange string

const (
	ChangeCommit          RunningChange = "commit"
	ChangeCommitConfirmed RunningChange = "commit_confirmed"
	ChangeRollback        RunningChange = "rollback"
	runtimeApplyFaultKey                = "runtime_apply_fault"
)

// RuntimeStore serializes promotion, runtime apply and compensating restoration.
// The callback must not call Store methods that acquire the store mutex. Its
// snapshots are detached; previous is nil when no running document exists.
type RuntimeStore interface {
	Store
	ApplyChange(context.Context, Revision, RunningChange, time.Duration, func(context.Context, *Config, *Config) error) (Revision, error)
	RuntimeApplyFault(context.Context) (string, error)
	SetRuntimeApplyFault(context.Context, string) error
}

// ApplyError reports the original failure and both compensating operations.
// Nil restore/reapply errors mean those operations succeeded.
//
// Recovery reports that the restored state is management recovery: the
// running configuration was refused at boot, so the store did not reapply
// it, and the caller must re-enter recovery and record the outcome in
// ReapplyError and the runtime apply fault.
type ApplyError struct {
	Err          error
	RestoreError error
	ReapplyError error
	HealthError  error
	Recovery     bool
}

func (e *ApplyError) Error() string {
	return fmt.Sprintf("apply failed: %v; restore: %v; reapply: %v; health: %v", e.Err, e.RestoreError, e.ReapplyError, e.HealthError)
}
func (e *ApplyError) Unwrap() error { return e.Err }

type savedConfigRow struct {
	key, data string
	updatedAt int64
}

// ApplyChange keeps readers, candidate writers and expiry callbacks out until
// the transition either succeeds or has been restored and reapplied. Recovery
// has its own bounded context: disconnecting the caller must not cancel it.
func (s *SQLiteStore) ApplyChange(ctx context.Context, expected Revision, change RunningChange, ttl time.Duration, apply func(context.Context, *Config, *Config) error) (Revision, error) {
	return s.applyTransition(ctx, func(capture func(*sql.Tx) error) (Revision, error) {
		switch change {
		case ChangeCommit:
			return s.promoteLocked(ctx, &expected, 0, capture)
		case ChangeCommitConfirmed:
			if ttl <= 0 {
				return "", errors.New("ttl must be > 0")
			}
			return s.promoteLocked(ctx, &expected, ttl, capture)
		case ChangeRollback:
			revision, err := s.rollbackLocked(ctx, &expected, capture)
			var invalid *ValidationError
			if errors.As(err, &invalid) {
				err = errors.Join(err, s.recordRollbackRefusal(ctx, err))
			}
			return revision, err
		default:
			return "", fmt.Errorf("unknown running change %q", change)
		}
	}, apply)
}

// ApplyReset replaces all configuration state with validated defaults, using
// the same restoration and runtime recovery as ApplyChange. Users and audit
// stores must only be cleared after it succeeds. The callback must not acquire
// the store mutex.
func (s *SQLiteStore) ApplyReset(ctx context.Context, expected Revision, defaults *Config, apply func(context.Context, *Config, *Config) error) (Revision, error) {
	if defaults == nil {
		return "", errors.New("config is nil")
	}
	if err := s.ValidateConfig(defaults); err != nil {
		return "", fmt.Errorf("config validation failed: %w", err)
	}
	return s.applyTransition(ctx, func(capture func(*sql.Tx) error) (Revision, error) {
		return s.resetLocked(ctx, expected, defaults, capture)
	}, apply)
}

func (s *SQLiteStore) applyTransition(ctx context.Context, transition func(func(*sql.Tx) error) (Revision, error), apply func(context.Context, *Config, *Config) error) (Revision, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var previous *Config
	var saved []savedConfigRow
	var bank []IDSRule
	recovering := false
	capture := func(tx *sql.Tx) error {
		var err error
		previous, err = loadRunningFrom(ctx, tx)
		if err != nil && !errors.Is(err, ErrNotFound) {
			return err
		}
		rows, err := tx.QueryContext(ctx, `SELECT key, data, updated_at FROM configs`)
		if err != nil {
			return err
		}
		for rows.Next() {
			var row savedConfigRow
			if err := rows.Scan(&row.key, &row.data, &row.updatedAt); err != nil {
				rows.Close()
				return err
			}
			saved = append(saved, row)
			recovering = recovering || row.key == bootFaultKey
		}
		err = rows.Err()
		rows.Close()
		if err != nil {
			return err
		}
		bank, err = loadIDSRulesFrom(ctx, tx)
		return err
	}
	// This handle excludes its own writers and timers. Another handle can
	// transition after the promotion commits; compensation compares the
	// promoted revision and refuses to overwrite that newer state. Defer collection
	// while these saved rows may be needed, even if the transition removes all
	// of their persisted references (notably reset and rollback).
	s.recoveryHoldsBanks = true
	defer func() { s.recoveryHoldsBanks = false }()
	revision, err := transition(capture)
	if err != nil {
		cleanupCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 30*time.Second)
		defer cancel()
		return "", errors.Join(err, s.finishBankRecoveryLocked(cleanupCtx))
	}
	next, observed, err := s.loadRunningRevisionLocked(ctx)
	if err == nil && observed != revision {
		err = errors.New("configuration changed during runtime apply")
	}
	if err == nil {
		err = apply(ctx, previous, next)
	}
	if err == nil {
		err = s.setRuntimeApplyFaultLocked(ctx, "")
	}
	if err == nil {
		// This is the last fallible operation on the success path. If collection
		// fails, its transaction rolls back without deleting recovery's banks;
		// compensate exactly as for a runtime failure.
		err = s.finishBankRecoveryLocked(ctx)
	}
	if err == nil {
		return revision, nil
	}
	s.recoveryHoldsBanks = true
	failure := &ApplyError{Err: err}
	recoveryCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 30*time.Second)
	defer cancel()
	failure.RestoreError = s.restoreApplyStateLocked(recoveryCtx, revision, saved, bank)
	switch {
	case failure.RestoreError != nil:
		failure.ReapplyError = errors.New("reapply not attempted: store restoration failed")
	case recovering:
		failure.Recovery = true
	case previous == nil:
		failure.ReapplyError = errors.New("no previous running document to reapply")
	default:
		failure.ReapplyError = apply(recoveryCtx, next, previous)
	}
	fault := ""
	if failure.RestoreError != nil || failure.ReapplyError != nil {
		fault = failure.Error()
	}
	if err := s.setRuntimeApplyFaultLocked(recoveryCtx, fault); err != nil {
		failure.HealthError = fmt.Errorf("record runtime apply health: %w", err)
	}
	if err := s.finishBankRecoveryLocked(recoveryCtx); err != nil {
		failure.HealthError = errors.Join(failure.HealthError, err)
	}
	return "", failure
}

func (s *SQLiteStore) restoreApplyStateLocked(ctx context.Context, expected Revision, saved []savedConfigRow, bank []IDSRule) error {
	tx, err := s.beginConfigTx(ctx, &expected)
	if err != nil {
		return err
	}
	defer tx.Rollback() //nolint:errcheck
	if _, err := tx.ExecContext(ctx, `DELETE FROM configs`); err != nil {
		return err
	}
	for _, row := range saved {
		if _, err := tx.ExecContext(ctx, `INSERT INTO configs (key, data, updated_at) VALUES (?, ?, ?)`, row.key, row.data, row.updatedAt); err != nil {
			return err
		}
	}
	if err := replaceIDSRulesTx(ctx, tx, bank); err != nil {
		return err
	}
	if _, err := s.commitRevisionTx(ctx, tx); err != nil {
		return err
	}
	s.stopPendingTimerLocked()
	pending, err := s.loadPending(ctx)
	if errors.Is(err, ErrNotFound) {
		return nil
	}
	if err != nil {
		return err
	}
	s.schedulePendingLocked(time.Until(time.Unix(0, pending.DeadlineUnix)))
	return nil
}

// RuntimeApplyFault survives management restarts until a successful replay.
func (s *SQLiteStore) RuntimeApplyFault(ctx context.Context) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.runtimeApplyFaultLocked(ctx)
}

func (s *SQLiteStore) runtimeApplyFaultLocked(ctx context.Context) (string, error) {
	var fault string
	err := s.db.QueryRowContext(ctx, `SELECT data FROM configs WHERE key = ?`, runtimeApplyFaultKey).Scan(&fault)
	if errors.Is(err, sql.ErrNoRows) {
		return "", nil
	}
	return fault, err
}

func (s *SQLiteStore) SetRuntimeApplyFault(ctx context.Context, fault string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.setRuntimeApplyFaultLocked(ctx, fault)
}
func (s *SQLiteStore) setRuntimeApplyFaultLocked(ctx context.Context, fault string) error {
	if fault == "" {
		_, err := s.db.ExecContext(ctx, `DELETE FROM configs WHERE key = ?`, runtimeApplyFaultKey)
		return err
	}
	_, err := s.db.ExecContext(ctx, `REPLACE INTO configs (key,data,updated_at) VALUES (?,?,?)`, runtimeApplyFaultKey, fault, time.Now().Unix())
	return err
}
