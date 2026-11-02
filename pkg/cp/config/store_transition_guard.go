// SPDX-License-Identifier: Apache-2.0
package config

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
)

type TransitionState string

const (
	// TransitionUncompleted is never safe to replay after an interrupted apply.
	TransitionUncompleted TransitionState = "uncompleted"
	// TransitionReapplyPending permits delivery of the restored authority only.
	TransitionReapplyPending TransitionState = "reapply_pending"
	TransitionBlocked        TransitionState = "restoration_blocked"
)

// TransitionGuard is uncertainty metadata, not a recovery journal. In
// particular, it cannot reconstruct history deleted by a reset.
type TransitionGuard struct {
	ID              string          `json:"id"`
	Revision        Revision        `json:"revision"`
	RunningRevision RunningRevision `json:"runningRevision"`
	State           TransitionState `json:"state"`
}

func readTransitionGuard(ctx context.Context, db configReader) (*TransitionGuard, error) {
	var raw string
	err := db.QueryRowContext(ctx, `SELECT data FROM runtime_transition WHERE id = 1`).Scan(&raw)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var guard TransitionGuard
	if err := json.Unmarshal([]byte(raw), &guard); err != nil {
		return nil, err
	}
	if !RunningRevision(guard.ID).Valid() || !guard.Revision.Valid() || !guard.RunningRevision.Valid() {
		return nil, errors.New("invalid runtime transition identity")
	}
	switch guard.State {
	case TransitionUncompleted, TransitionReapplyPending, TransitionBlocked:
	default:
		return nil, errors.New("invalid runtime transition state")
	}
	return &guard, nil
}

func writeTransitionGuardTx(ctx context.Context, tx *sql.Tx, guard *TransitionGuard) error {
	blob, err := json.Marshal(guard)
	if err != nil {
		return err
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO runtime_transition (id, data) VALUES (1, ?)
 ON CONFLICT(id) DO UPDATE SET data = excluded.data`, string(blob))
	return err
}

func establishTransitionTx(ctx context.Context, tx *sql.Tx, synchronous bool) error {
	token, err := readRunningIdentity(ctx, tx, configKeyRunning)
	if err != nil {
		return err
	}
	id, err := mintRunningRevision()
	if err != nil {
		return err
	}
	revision, err := nextRevisionTx(ctx, tx)
	if err != nil {
		return err
	}
	state := TransitionReapplyPending
	if synchronous {
		state = TransitionUncompleted
	}
	return writeTransitionGuardTx(ctx, tx, &TransitionGuard{
		ID: string(id), Revision: revision,
		RunningRevision: token, State: state,
	})
}

var ErrTransitionMismatch = errors.New("runtime transition no longer current")

// CompleteRuntimeApply clears only restored/accepted replay-pending work.
// Uncompleted/blocked guards require an explicit validated transition, not a
// retry, fault-string clear, read or boot replay.
func (s *SQLiteStore) CompleteRuntimeApply(ctx context.Context, target RunningRevision, transitionID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.completeRuntimeApplyLocked(ctx, target, transitionID, false)
}

func (s *SQLiteStore) completeRuntimeApplyLocked(ctx context.Context, target RunningRevision, id string, synchronous bool) error {
	tx, err := s.beginConfigTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback() //nolint:errcheck
	current, err := readRunningIdentity(ctx, tx, configKeyRunning)
	if err != nil {
		return err
	}
	guard, err := readTransitionGuard(ctx, tx)
	if err != nil {
		return err
	}
	if current != target || guard != nil && (guard.ID != id || guard.RunningRevision != target ||
		!synchronous && guard.State != TransitionReapplyPending) || guard == nil && id != "" {
		return ErrTransitionMismatch
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM runtime_transition WHERE id = 1`); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM configs WHERE key = ?`, runtimeApplyFaultKey); err != nil {
		return err
	}
	// Bank collection and all other fallible steps precede this final commit.
	return s.commitStateTx(ctx, tx)
}

// SetStoreNotify registers a coalescing, nonblocking state-change signal.
// Receivers reread authority and own the channel; they must not close it.
func (s *SQLiteStore) SetStoreNotify(notify chan<- struct{}) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.storeNotify = notify
}

func (s *SQLiteStore) notifyStoreLocked() {
	select {
	case s.storeNotify <- struct{}{}:
	default:
	}
}

func (s *SQLiteStore) enterApply(ctx context.Context) error {
	select {
	case s.applyGate <- struct{}{}:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (s *SQLiteStore) leaveApply() { <-s.applyGate }
