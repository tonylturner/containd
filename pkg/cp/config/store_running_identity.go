// SPDX-License-Identifier: Apache-2.0
package config

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"github.com/tonylturner/containd/pkg/common/protection"
)

// RunningRevision is an equality-only identity, independent of whole-state CAS.
// It covers the persisted document and its resolved IDS bank, not file bytes.
type RunningRevision string

func (r RunningRevision) Valid() bool {
	return protection.ValidRunningRevision(protection.Revision(r))
}

// RunningSnapshot is detached from persistence. PendingConfirm belongs to this
// generation and is supplied to effects so they never need to reread the store.
type RunningSnapshot struct {
	*Config
	RunningRevision RunningRevision
	PendingConfirm  *PendingConfirm
}

// RunningState is a coherent coordinator read. A nil Running means there is no
// desired document; a surviving Transition still forbids blind normal replay.
type RunningState struct {
	Running    *RunningSnapshot
	Revision   Revision
	Transition *TransitionGuard
}

func (s *SQLiteStore) ReadRunning(ctx context.Context) (RunningState, error) {
	snapshot, err := s.ReadSnapshot(ctx, SnapshotRunning, true)
	if err != nil {
		return RunningState{}, err
	}
	state := RunningState{Revision: snapshot.Revision, Transition: snapshot.Transition}
	if snapshot.Running != nil {
		state.Running = &RunningSnapshot{
			Config: snapshot.Running, RunningRevision: snapshot.RunningRevision, PendingConfirm: snapshot.PendingConfirm,
		}
	}
	return state, nil
}

func mintRunningRevision() (RunningRevision, error) {
	var token [24]byte
	if _, err := rand.Read(token[:]); err != nil {
		return "", err
	}
	return RunningRevision(hex.EncodeToString(token[:])), nil
}

func readRunningIdentity(ctx context.Context, db configReader, key string) (RunningRevision, error) {
	var token RunningRevision
	err := db.QueryRowContext(ctx, `SELECT token FROM running_identity WHERE key = ?`, key).Scan(&token)
	if err != nil {
		return "", fmt.Errorf("%s identity: %w", key, err)
	}
	if !token.Valid() {
		return "", fmt.Errorf("invalid %s identity", key)
	}
	return token, nil
}

func writeRunningIdentityTx(ctx context.Context, tx *sql.Tx, key string, token RunningRevision) error {
	_, err := tx.ExecContext(ctx, `INSERT INTO running_identity (key, token) VALUES (?, ?)
 ON CONFLICT(key) DO UPDATE SET token = excluded.token`, key, token)
	return err
}

func mintIdentityTx(ctx context.Context, tx *sql.Tx, key string) error {
	if key != configKeyRunning && key != configKeyPrevious {
		return nil
	}
	var initialized, exists int
	if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM running_identity_genesis`).Scan(&initialized); err != nil {
		return err
	}
	if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM running_identity WHERE key = ?`, key).Scan(&exists); err != nil {
		return err
	}
	if initialized == 0 && exists == 0 {
		// A legacy document gets its first public identity only after all
		// content migrations, never at an intermediate representation.
		return nil
	}
	if err := replaceIdentityTx(ctx, tx, key); err != nil {
		return err
	}
	if key != configKeyRunning {
		return nil
	}
	// Content migrations and direct writes must carry unresolved uncertainty
	// forward, not strand a replay-pending guard on an obsolete token.
	guard, err := readTransitionGuard(ctx, tx)
	if err != nil || guard == nil {
		return err
	}
	guard.RunningRevision, err = readRunningIdentity(ctx, tx, key)
	if err != nil {
		return err
	}
	guard.Revision, err = nextRevisionTx(ctx, tx)
	if err != nil {
		return err
	}
	return writeTransitionGuardTx(ctx, tx, guard)
}

func replaceIdentityTx(ctx context.Context, tx *sql.Tx, key string) error {
	token, err := mintRunningRevision()
	if err != nil {
		return err
	}
	return writeRunningIdentityTx(ctx, tx, key, token)
}

// validateIdentities runs before migrations on subsequent opens. Missing
// metadata after genesis is corruption, never an invitation to infer from CAS.
func validateIdentities(ctx context.Context, db configReader) error {
	var initialized int
	err := db.QueryRowContext(ctx, `SELECT id FROM running_identity_genesis WHERE id = 1`).Scan(&initialized)
	if errors.Is(err, sql.ErrNoRows) {
		return nil
	}
	if err != nil {
		return err
	}
	for _, key := range []string{configKeyRunning, configKeyPrevious} {
		var present int
		if err := db.QueryRowContext(ctx, `SELECT COUNT(*) FROM configs WHERE key = ?`, key).Scan(&present); err != nil {
			return err
		}
		if present != 0 {
			if _, err := readRunningIdentity(ctx, db, key); err != nil {
				return err
			}
		}
	}
	return nil
}

// Genesis follows all content migrations and precedes pending expiry. Its
// marker and both identities commit atomically; concurrent opens are idempotent.
func (s *SQLiteStore) initializeRunningIdentities(ctx context.Context) error {
	tx, err := s.beginConfigTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback() //nolint:errcheck
	var initialized int
	err = tx.QueryRowContext(ctx, `SELECT id FROM running_identity_genesis WHERE id = 1`).Scan(&initialized)
	if err == nil {
		if err := validateIdentities(ctx, tx); err != nil {
			return err
		}
		return s.commitStateTx(ctx, tx)
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return err
	}
	for _, key := range []string{configKeyRunning, configKeyPrevious} {
		var present int
		if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM configs WHERE key = ?`, key).Scan(&present); err != nil {
			return err
		}
		if present != 0 {
			if err := replaceIdentityTx(ctx, tx, key); err != nil {
				return err
			}
		}
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO running_identity_genesis (id) VALUES (1)`); err != nil {
		return err
	}
	return s.commitStateTx(ctx, tx)
}

func readLabelledRunning(ctx context.Context, db configReader) (*RunningSnapshot, error) {
	cfg, err := loadRunningFrom(ctx, db)
	if err != nil {
		return nil, err
	}
	token, err := readRunningIdentity(ctx, db, configKeyRunning)
	if err != nil {
		return nil, err
	}
	pending, err := readPendingConfirm(ctx, db)
	if err != nil {
		return nil, err
	}
	return &RunningSnapshot{Config: cfg, RunningRevision: token, PendingConfirm: pending}, nil
}

func readPendingConfirm(ctx context.Context, db configReader) (*PendingConfirm, error) {
	pending, err := loadPendingFrom(ctx, db)
	if errors.Is(err, ErrNotFound) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &PendingConfirm{Deadline: time.Unix(0, pending.DeadlineUnix).UTC()}, nil
}
