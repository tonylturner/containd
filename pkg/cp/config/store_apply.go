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
	ReadRunning(context.Context) (RunningState, error)
	ApplyChange(context.Context, Revision, RunningChange, time.Duration, func(context.Context, *RunningSnapshot, *RunningSnapshot) error) (Revision, error)
	ApplyReset(context.Context, Revision, *Config, func(context.Context, *RunningSnapshot, *RunningSnapshot) error) (Revision, error)
	CompleteRuntimeApply(context.Context, RunningRevision, string) error
	SetStoreNotify(chan<- struct{})
	RuntimeApplyFault(context.Context) (string, error)
	SetRuntimeApplyFault(context.Context, RunningRevision, string) error
}

// ApplyError reports the original failure and both compensating operations.
// Nil restore/reapply errors mean those operations succeeded.
//
// Recovery reports that the restored state was refused at boot or already
// uncertain. The store did not reapply it; the caller must re-enter recovery
// and record the outcome without resolving the blocked guard.
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

// ApplyChange serializes synchronous transitions and expiry, but releases the
// store mutex for every runtime effect. Recovery
// has its own bounded context: disconnecting the caller must not cancel it.
func (s *SQLiteStore) ApplyChange(ctx context.Context, expected Revision, change RunningChange, ttl time.Duration, apply func(context.Context, *RunningSnapshot, *RunningSnapshot) error) (Revision, error) {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
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
func (s *SQLiteStore) ApplyReset(ctx context.Context, expected Revision, defaults *Config, apply func(context.Context, *RunningSnapshot, *RunningSnapshot) error) (Revision, error) {
	if defaults == nil {
		return "", errors.New("config is nil")
	}
	if err := s.ValidateConfig(defaults); err != nil {
		return "", fmt.Errorf("config validation failed: %w", err)
	}
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	return s.applyTransition(ctx, func(capture func(*sql.Tx) error) (Revision, error) {
		return s.resetLocked(ctx, expected, defaults, capture)
	}, apply)
}

func (s *SQLiteStore) applyTransition(ctx context.Context, transition func(func(*sql.Tx) error) (Revision, error), apply func(context.Context, *RunningSnapshot, *RunningSnapshot) error) (Revision, error) {
	if apply == nil {
		return "", errors.New("runtime apply callback is nil")
	}
	if err := s.enterApply(ctx); err != nil {
		return "", err
	}
	defer s.leaveApply()
	s.mu.Lock()
	defer s.mu.Unlock()
	var previous *RunningSnapshot
	var saved []savedConfigRow
	var identities = map[string]RunningRevision{}
	var bank []IDSRule
	var banks []savedBank
	recovering := false
	capture := func(tx *sql.Tx) error {
		var err error
		previous, err = readLabelledRunning(ctx, tx)
		if err != nil && !errors.Is(err, ErrNotFound) {
			return err
		}
		guard, err := readTransitionGuard(ctx, tx)
		if err != nil {
			return err
		}
		recovering = guard != nil && guard.State != TransitionReapplyPending
		for _, key := range []string{configKeyRunning, configKeyPrevious} {
			var token RunningRevision
			err := tx.QueryRowContext(ctx, `SELECT token FROM running_identity WHERE key = ?`, key).Scan(&token)
			if err == nil {
				identities[key] = token
			} else if !errors.Is(err, sql.ErrNoRows) {
				return err
			}
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
		banks, err = captureRecoveryBanks(ctx, tx)
		if err != nil {
			return err
		}
		bank, err = loadIDSRulesFrom(ctx, tx)
		return err
	}
	// Recovery owns detached bank copies: other handles may collect generations.
	s.recoveryHoldsBanks = true
	defer func() { s.recoveryHoldsBanks = false }()
	forwardCtx, forwardCancel := context.WithTimeout(ctx, 30*time.Second)
	defer forwardCancel()
	revision, err := transition(capture)
	if err != nil {
		cleanupCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 30*time.Second)
		defer cancel()
		return "", errors.Join(err, s.finishBankRecoveryLocked(cleanupCtx))
	}
	next, observed, err := s.loadRunningRevisionLocked(forwardCtx)
	var guard *TransitionGuard
	if err == nil {
		guard, err = readTransitionGuard(forwardCtx, s.db)
	}
	if err == nil && (observed != revision || guard == nil || guard.RunningRevision != next.RunningRevision) {
		err = ErrTransitionMismatch
	}
	if err == nil {
		err = s.applyUnlocked(forwardCtx, apply, previous, next)
	}
	if err == nil {
		err = s.finishBankRecoveryLocked(forwardCtx)
	}
	if err == nil {
		err = s.completeRuntimeApplyLocked(forwardCtx, next.RunningRevision, guard.ID, true)
	}
	if err == nil {
		return revision, nil
	}
	s.recoveryHoldsBanks = true
	failure := &ApplyError{Err: err}
	recoveryCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 30*time.Second)
	defer cancel()
	var restored *RunningSnapshot
	var restoredGuard *TransitionGuard
	restored, restoredGuard, failure.RestoreError = s.restoreApplyStateLocked(recoveryCtx, revision, saved, identities, bank, banks, recovering)
	switch {
	case failure.RestoreError != nil:
		failure.ReapplyError = errors.New("reapply not attempted: store restoration failed")
	case recovering:
		failure.Recovery = true
	case restored == nil:
		failure.ReapplyError = errors.New("no previous running document to reapply")
	default:
		failure.ReapplyError = s.applyUnlocked(recoveryCtx, apply, next, restored)
	}
	var mismatch *ErrRevisionMismatch
	if errors.As(failure.RestoreError, &mismatch) {
		// Never attach a stale failure or clear the newer authority's guard.
		failure.HealthError = s.finishBankRecoveryLocked(recoveryCtx)
		return "", failure
	}
	if failure.RestoreError != nil {
		failure.HealthError = s.blockTransitionLocked(recoveryCtx, revision, failure.Error())
	} else {
		fault := ""
		if failure.ReapplyError != nil || recovering {
			fault = failure.Error()
		}
		failure.HealthError = s.recordTransitionFaultLocked(recoveryCtx, restoredGuard, fault)
	}
	if err := s.finishBankRecoveryLocked(recoveryCtx); err != nil {
		failure.HealthError = errors.Join(failure.HealthError, err)
	}
	if failure.RestoreError == nil && failure.ReapplyError == nil && !recovering && failure.HealthError == nil {
		if err := s.completeRuntimeApplyLocked(recoveryCtx, restored.RunningRevision, restoredGuard.ID, true); err != nil {
			failure.HealthError = err
		}
	}
	return "", failure
}

// Effects never run under mu. The coordinator owns supersession and callback
// cancellation; this gate serializes synchronous transitions/expiry per handle.
func (s *SQLiteStore) applyUnlocked(ctx context.Context, apply func(context.Context, *RunningSnapshot, *RunningSnapshot) error, previous, next *RunningSnapshot) error {
	s.mu.Unlock()
	defer s.mu.Lock()
	err := apply(ctx, previous, next)
	if err == nil {
		err = ctx.Err()
	}
	return err
}

func (s *SQLiteStore) restoreApplyStateLocked(ctx context.Context, expected Revision, saved []savedConfigRow, identities map[string]RunningRevision, bank []IDSRule, banks []savedBank, recovering bool) (*RunningSnapshot, *TransitionGuard, error) {
	tx, err := s.beginConfigTx(ctx, &expected)
	if err != nil {
		return nil, nil, err
	}
	defer tx.Rollback() //nolint:errcheck
	guard, err := readTransitionGuard(ctx, tx)
	if err != nil {
		return nil, nil, err
	}
	if guard == nil {
		return nil, nil, ErrTransitionMismatch
	}
	for _, b := range banks {
		if _, err := tx.ExecContext(ctx, `INSERT INTO ids_banks (id, data) VALUES (?, ?) ON CONFLICT(id) DO NOTHING`, b.id, b.data); err != nil {
			return nil, nil, err
		}
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM configs`); err != nil {
		return nil, nil, err
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM running_identity`); err != nil {
		return nil, nil, err
	}
	for _, row := range saved {
		if _, err := tx.ExecContext(ctx, `INSERT INTO configs (key, data, updated_at) VALUES (?, ?, ?)`, row.key, row.data, row.updatedAt); err != nil {
			return nil, nil, err
		}
	}
	for key, token := range identities {
		if err := writeRunningIdentityTx(ctx, tx, key, token); err != nil {
			return nil, nil, err
		}
	}
	if err := replaceIDSRulesTx(ctx, tx, bank); err != nil {
		return nil, nil, err
	}
	var restored *RunningSnapshot
	if _, exists := identities[configKeyRunning]; exists {
		if err := mintIdentityTx(ctx, tx, configKeyRunning); err != nil {
			return nil, nil, err
		}
		restored, err = readLabelledRunning(ctx, tx)
		if err != nil {
			return nil, nil, err
		}
		guard.RunningRevision = restored.RunningRevision
	}
	guard.State = TransitionReapplyPending
	if restored == nil || recovering {
		guard.State = TransitionBlocked
	}
	guard.Revision, err = nextRevisionTx(ctx, tx)
	if err != nil {
		return nil, nil, err
	}
	if err := writeTransitionGuardTx(ctx, tx, guard); err != nil {
		return nil, nil, err
	}
	if _, err := s.commitRevisionTx(ctx, tx); err != nil {
		return nil, nil, err
	}
	s.stopPendingTimerLocked()
	if restored != nil && restored.PendingConfirm != nil {
		s.schedulePendingLocked(time.Until(restored.PendingConfirm.Deadline))
	}
	return restored, guard, nil
}

func (s *SQLiteStore) recordTransitionFaultLocked(ctx context.Context, expected *TransitionGuard, fault string) error {
	tx, err := s.beginConfigTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback() //nolint:errcheck
	guard, err := readTransitionGuard(ctx, tx)
	if err != nil {
		return err
	}
	if guard == nil || expected == nil || *guard != *expected {
		return ErrTransitionMismatch
	}
	current, err := readRunningIdentity(ctx, tx, configKeyRunning)
	var runningRows int
	if errors.Is(err, sql.ErrNoRows) && expected.State == TransitionBlocked {
		if countErr := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM configs WHERE key = ?`, configKeyRunning).Scan(&runningRows); countErr != nil {
			return countErr
		}
		if runningRows == 0 {
			// Restoring an originally empty store leaves no desired generation,
			// but its failed transition still needs durable diagnostics.
			err = nil
			current = expected.RunningRevision
		}
	}
	if err != nil || current != expected.RunningRevision {
		return errors.Join(ErrTransitionMismatch, err)
	}
	if fault != "" {
		if _, err := tx.ExecContext(ctx, `REPLACE INTO configs (key,data,updated_at) VALUES (?,?,?)`, runtimeApplyFaultKey, fault, time.Now().Unix()); err != nil {
			return err
		}
	}
	return s.commitStateTx(ctx, tx)
}

func (s *SQLiteStore) blockTransitionLocked(ctx context.Context, revision Revision, fault string) error {
	tx, err := s.beginConfigTx(ctx, &revision)
	if err != nil {
		return err
	}
	defer tx.Rollback() //nolint:errcheck
	guard, err := readTransitionGuard(ctx, tx)
	if err != nil {
		return err
	}
	if guard == nil || guard.Revision != revision {
		return ErrTransitionMismatch
	}
	guard.State = TransitionBlocked
	if err := writeTransitionGuardTx(ctx, tx, guard); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `REPLACE INTO configs (key,data,updated_at) VALUES (?,?,?)`, runtimeApplyFaultKey, fault, time.Now().Unix()); err != nil {
		return err
	}
	return s.commitStateTx(ctx, tx)
}

// RuntimeApplyFault is diagnostic text; clearing it never resolves a guard.
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

// SetRuntimeApplyFault records generation-bound diagnostics. A fault-string
// clear cannot resolve an active transition; use CompleteRuntimeApply instead.
func (s *SQLiteStore) SetRuntimeApplyFault(ctx context.Context, target RunningRevision, fault string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	tx, err := s.beginConfigTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback() //nolint:errcheck
	current, err := readRunningIdentity(ctx, tx, configKeyRunning)
	if err != nil {
		return err
	}
	if current != target {
		return ErrTransitionMismatch
	}
	if fault == "" {
		guard, guardErr := readTransitionGuard(ctx, tx)
		if guardErr != nil {
			return guardErr
		}
		if guard != nil {
			return ErrTransitionMismatch
		}
		_, err = tx.ExecContext(ctx, `DELETE FROM configs WHERE key = ?`, runtimeApplyFaultKey)
	} else {
		_, err = tx.ExecContext(ctx, `REPLACE INTO configs (key,data,updated_at) VALUES (?,?,?)`, runtimeApplyFaultKey, fault, time.Now().Unix())
	}
	if err != nil {
		return err
	}
	return s.commitStateTx(ctx, tx)
}
