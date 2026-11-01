// SPDX-License-Identifier: Apache-2.0
package config

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"regexp"
	"time"
)

// Revision is an opaque identity of the entire persisted configuration state.
type Revision string

var revisionPattern = regexp.MustCompile(`^[0-9a-f]{16}\.[1-9][0-9]*$`)

func (r Revision) Valid() bool { return len(r) <= 64 && revisionPattern.MatchString(string(r)) }

// ErrRevisionMismatch carries the authority observed by the locked comparison.
type ErrRevisionMismatch struct{ CurrentRevision Revision }

func (e *ErrRevisionMismatch) Error() string { return "configuration changed since it was read" }

// SnapshotKind selects documents without decoding unrelated persisted state.
// SnapshotRevision is useful for internal intent fixtures; clients should read
// the actual document their edit is based on.
type SnapshotKind uint8

const (
	SnapshotRevision SnapshotKind = iota
	SnapshotRunning
	SnapshotCandidate
	SnapshotPair
	SnapshotIDS
)

// ConfigSnapshot contains detached documents and their shared revision. An
// absent candidate is represented by running, without persisting a candidate.
type ConfigSnapshot struct {
	Running, Candidate *Config
	Revision           Revision
	IDSRules           []IDSRule
	PendingConfirm     *PendingConfirm
}

// PendingConfirm is server-owned commit-confirmed state.
type PendingConfirm struct {
	Deadline time.Time `json:"deadline"`
}

func readRevision(ctx context.Context, db configReader) (Revision, error) {
	var epoch string
	var counter int64
	err := db.QueryRowContext(ctx, `SELECT epoch, counter FROM config_revision WHERE id = 1`).Scan(&epoch, &counter)
	return Revision(fmt.Sprintf("%s.%d", epoch, counter)), err
}

// beginConfigTx takes the SQLite write lock before reading anything. The
// no-op update obtains the lock without consuming a revision on rejection.
func (s *SQLiteStore) beginConfigTx(ctx context.Context, expected *Revision) (*sql.Tx, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	if _, err = tx.ExecContext(ctx, `UPDATE config_revision SET counter = counter WHERE id = 1`); err == nil && expected != nil {
		var current Revision
		current, err = readRevision(ctx, tx)
		if err == nil && current != *expected {
			err = &ErrRevisionMismatch{CurrentRevision: current}
		}
	}
	if err != nil {
		_ = tx.Rollback()
		return nil, err
	}
	return tx, nil
}

func (s *SQLiteStore) commitRevisionTx(ctx context.Context, tx *sql.Tx) (Revision, error) {
	var epoch string
	var counter int64
	if err := tx.QueryRowContext(ctx, `UPDATE config_revision SET counter = counter + 1 WHERE id = 1 RETURNING epoch, counter`).Scan(&epoch, &counter); err != nil {
		return "", err
	}
	if err := s.commitStateTx(ctx, tx); err != nil {
		return "", err
	}
	return Revision(fmt.Sprintf("%s.%d", epoch, counter)), nil
}

// ReadSnapshot reads documents, bank references and revision in one database
// snapshot, including when another handle writes to the same database.
func (s *SQLiteStore) ReadSnapshot(ctx context.Context, kind SnapshotKind, withBank bool) (ConfigSnapshot, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	tx, err := s.db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return ConfigSnapshot{}, err
	}
	defer tx.Rollback() //nolint:errcheck
	var result ConfigSnapshot
	result.Revision, err = readRevision(ctx, tx)
	if err != nil {
		return result, err
	}
	if kind == SnapshotRunning || kind == SnapshotPair {
		result.Running, err = readKindFrom(ctx, tx, configKeyRunning, withBank)
		if err != nil && err != ErrNotFound {
			return result, err
		}
	}
	if kind == SnapshotCandidate || kind == SnapshotPair {
		result.Candidate, err = loadCandidateFrom(ctx, tx, withBank)
		if err != nil && err != ErrNotFound {
			return result, err
		}
	}
	if kind == SnapshotPair {
		pending, pendingErr := loadPendingFrom(ctx, tx)
		if pendingErr != nil && !errors.Is(pendingErr, ErrNotFound) {
			return result, pendingErr
		}
		if pending != nil {
			result.PendingConfirm = &PendingConfirm{Deadline: time.Unix(0, pending.DeadlineUnix).UTC()}
		}
	}
	if kind == SnapshotIDS {
		result.IDSRules, err = loadIDSRulesFrom(ctx, tx)
		if err != nil {
			return result, err
		}
	}
	return result, tx.Commit()
}

// loadRunningRevisionLocked prevents runtime apply from accidentally loading a
// different handle's subsequently committed running document.
func (s *SQLiteStore) loadRunningRevisionLocked(ctx context.Context) (*Config, Revision, error) {
	tx, err := s.db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return nil, "", err
	}
	defer tx.Rollback() //nolint:errcheck
	revision, err := readRevision(ctx, tx)
	if err != nil {
		return nil, "", err
	}
	cfg, err := loadRunningFrom(ctx, tx)
	if err != nil {
		return nil, "", err
	}
	return cfg, revision, tx.Commit()
}
