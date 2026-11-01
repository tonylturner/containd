// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

package config

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"
)

// LoadCandidate reads desired state. An absent candidate is represented by
// running in memory, so seeding and diff reads never persist pending changes.
func (s *SQLiteStore) LoadCandidate(ctx context.Context) (*Config, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.loadCandidateLocked(ctx)
}

func (s *SQLiteStore) loadCandidateLocked(ctx context.Context) (*Config, error) {
	return loadCandidateFrom(ctx, s.db, true)
}

// LoadCandidateDocument reads editable settings without loading the rule bank.
// Callers must not interpret its absent rules as an empty stored bank.
func (s *SQLiteStore) LoadCandidateDocument(ctx context.Context) (*Config, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return loadCandidateFrom(ctx, s.db, false)
}

func loadCandidateFrom(ctx context.Context, db configReader, withBank bool) (*Config, error) {
	cfg, err := readKindFrom(ctx, db, configKeyCandidate, withBank)
	if errors.Is(err, ErrNotFound) {
		return readKindFrom(ctx, db, configKeyRunning, withBank)
	}
	return cfg, err
}

// IDSCandidateStore exposes edits that deliberately read or replace the bank.
// Store's ordinary mutation contract excludes it.
type IDSCandidateStore interface {
	Store
	MutateCandidateIDS(context.Context, func(*Config) error) error
}

// PairedStore reads both desired states from the same serialized boundary.
type PairedStore interface {
	Store
	LoadPair(context.Context) (*Config, *Config, error)
}

// LoadPair returns detached running and candidate snapshots. Missing documents
// are nil; an absent candidate is seeded in memory, just like LoadCandidate.
func (s *SQLiteStore) LoadPair(ctx context.Context) (*Config, *Config, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	running, err := s.loadRunningLocked(ctx)
	if err != nil && !errors.Is(err, ErrNotFound) {
		return nil, nil, err
	}
	candidate, err := s.loadCandidateLocked(ctx)
	if err != nil && !errors.Is(err, ErrNotFound) {
		return nil, nil, err
	}
	return running, candidate, nil
}

// MutateCandidate never loads, validates or rewrites the bank. The callback
// receives nil rules and must leave them nil; it must not call Store methods.
func (s *SQLiteStore) MutateCandidate(ctx context.Context, edit func(*Config) error) error {
	return s.mutateCandidate(ctx, edit, false)
}

// MutateCandidateIDS supplies a complete detached bank to the callback.
func (s *SQLiteStore) MutateCandidateIDS(ctx context.Context, edit func(*Config) error) error {
	return s.mutateCandidate(ctx, edit, true)
}

func (s *SQLiteStore) mutateCandidate(ctx context.Context, edit func(*Config) error, withBank bool) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	cfg, err := loadCandidateFrom(ctx, s.db, withBank)
	if err != nil {
		return err
	}
	if err := edit(cfg); err != nil {
		return err
	}
	if !withBank && cfg.IDS.Rules != nil {
		return errors.New("bank-free candidate edit supplied IDS rules")
	}
	// nil from a bank-aware edit means an authoritative empty bank, not retain.
	if withBank && cfg.IDS.Rules == nil {
		cfg.IDS.Rules = []IDSRule{}
	}
	return s.saveKind(ctx, configKeyCandidate, cfg)
}

// SaveCandidate retains an omitted bank; an explicit empty bank clears it.
func (s *SQLiteStore) SaveCandidate(ctx context.Context, cfg *Config) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.saveKind(ctx, configKeyCandidate, cfg)
}

func writeConfigTx(ctx context.Context, tx *sql.Tx, key string, cfg *Config) error {
	id, err := bankReference(ctx, tx, key)
	if err != nil {
		return err
	}
	if id == 0 && key == configKeyCandidate {
		id, err = bankReference(ctx, tx, configKeyRunning)
		if err != nil {
			return err
		}
	}
	if cfg.IDS.Rules != nil || id == 0 {
		rules := cfg.IDS.Rules
		// Save may create the first running document after SaveIDSRules.
		// An omitted bank retains that already persisted standalone bank too.
		if id == 0 && key == configKeyRunning && rules == nil {
			rules, err = loadIDSRulesFrom(ctx, tx)
			if err != nil {
				return err
			}
		}
		id, err = createBankTx(ctx, tx, rules)
		if err != nil {
			return err
		}
	}
	return writeReferencedConfigTx(ctx, tx, key, cfg, id)
}

func writeReferencedConfigTx(ctx context.Context, tx *sql.Tx, key string, cfg *Config, id int64) error {
	if err := persistScopeMigrationTx(ctx, tx, cfg.scopeMigration); err != nil {
		return err
	}
	if err := persistRuleModeMigrationTx(ctx, tx, key, cfg.modeMigration); err != nil {
		return err
	}
	stored := storedConfig{Config: *cfg, SnapshotFormat: snapshotFormatReferencedBank, BankID: id}
	stored.IDS.Rules = nil
	blob, err := json.Marshal(stored)
	if err != nil {
		return err
	}
	_, err = tx.ExecContext(ctx, `REPLACE INTO configs (key, data, updated_at) VALUES (?, ?, ?)`, key, string(blob), time.Now().Unix())
	return err
}

// Promotions move immutable references. Only a changed running bank needs to
// be materialized into ids_rules, the engine's existing consumer table.
func (s *SQLiteStore) promoteLocked(ctx context.Context, ttl time.Duration) error {
	candidate, err := s.loadCandidateLocked(ctx)
	if err != nil {
		return err
	}
	baseline, err := readKindFrom(ctx, s.db, configKeyRunning, false)
	if err != nil && !errors.Is(err, ErrNotFound) {
		return err
	}
	if err := s.checkWrite(baseline, candidate); err != nil {
		return err
	}
	if err := s.validateSSHAccessLocked(ctx, candidate); err != nil {
		return err
	}
	running, err := readKindFrom(ctx, s.db, configKeyRunning, false)
	if err != nil && !errors.Is(err, ErrNotFound) {
		return err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback() //nolint:errcheck
	if candidate.scopeMigration != nil || candidate.modeMigration != nil {
		if err := writeConfigTx(ctx, tx, configKeyCandidate, candidate); err != nil {
			return err
		}
	}
	runningID, err := bankReference(ctx, tx, configKeyRunning)
	if err != nil {
		return err
	}
	candidateID, err := bankReference(ctx, tx, configKeyCandidate)
	if err != nil {
		return err
	}
	if candidateID == 0 {
		candidateID = runningID
	}
	if running != nil {
		if err := writeReferencedConfigTx(ctx, tx, configKeyPrevious, running, runningID); err != nil {
			return err
		}
	}
	if candidateID != runningID {
		if err := replaceIDSRulesTx(ctx, tx, candidate.IDS.Rules); err != nil {
			return err
		}
	}
	if err := writeReferencedConfigTx(ctx, tx, configKeyRunning, candidate, candidateID); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM configs WHERE key IN (?, ?, ?)`, configKeyCandidate, configKeyPending, bootFaultKey); err != nil {
		return err
	}
	if ttl > 0 {
		blob, err := json.Marshal(pendingCommit{DeadlineUnix: time.Now().Add(ttl).UnixNano()})
		if err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, `REPLACE INTO configs (key, data, updated_at) VALUES (?, ?, ?)`, configKeyPending, string(blob), time.Now().Unix()); err != nil {
			return err
		}
	}
	if err := s.commitStateTx(ctx, tx); err != nil {
		return err
	}
	s.stopPendingTimerLocked()
	if ttl > 0 {
		s.schedulePendingLocked(ttl)
	}
	return nil
}

func writeRunningTx(ctx context.Context, tx *sql.Tx, cfg *Config) error {
	if err := replaceIDSRulesTx(ctx, tx, cfg.IDS.Rules); err != nil {
		return err
	}
	// A reset's nil bank is authoritative, unlike Save's retain semantics.
	cp := *cfg
	if cp.IDS.Rules == nil {
		cp.IDS.Rules = []IDSRule{}
	}
	return writeConfigTx(ctx, tx, configKeyRunning, &cp)
}

func (s *SQLiteStore) rollbackLocked(ctx context.Context) error {
	prev, err := s.loadKind(ctx, configKeyPrevious)
	if err != nil {
		return err
	}
	if err := s.checkStored(prev); err != nil {
		if recordErr := s.recordRollbackRefusal(ctx, err); recordErr != nil {
			return fmt.Errorf("record rollback refusal (%v): %w", err, recordErr)
		}
		return err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback() //nolint:errcheck
	if prev.scopeMigration != nil || prev.modeMigration != nil {
		// Pin the upgraded bank in previous too, so repeated rollbacks cannot
		// re-migrate the same historical snapshot or reuse its obsolete bank.
		if err := writeConfigTx(ctx, tx, configKeyPrevious, prev); err != nil {
			return err
		}
	}
	id, err := bankReference(ctx, tx, configKeyPrevious)
	if err != nil {
		return err
	}
	if id == 0 {
		return errors.New("previous snapshot has no IDS bank reference")
	}
	runningID, err := bankReference(ctx, tx, configKeyRunning)
	if err != nil {
		return err
	}
	if runningID != id {
		if err := replaceIDSRulesTx(ctx, tx, prev.IDS.Rules); err != nil {
			return err
		}
	}
	if err := writeReferencedConfigTx(ctx, tx, configKeyRunning, prev, id); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM configs WHERE key IN (?, ?)`, configKeyPending, bootFaultKey); err != nil {
		return err
	}
	if err := s.commitStateTx(ctx, tx); err != nil {
		return err
	}
	s.stopPendingTimerLocked()
	return nil
}

func (s *SQLiteStore) stopPendingTimerLocked() {
	if s.pendingTimer != nil {
		s.pendingTimer.Stop()
		s.pendingTimer = nil
	}
}
