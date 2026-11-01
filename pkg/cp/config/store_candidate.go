// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

package config

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
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
	MutateCandidateIDS(context.Context, Revision, func(*Config) error) (Revision, error)
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
func (s *SQLiteStore) MutateCandidate(ctx context.Context, expected Revision, edit func(*Config) error) (Revision, error) {
	return s.mutateCandidate(ctx, expected, edit, false)
}

// MutateCandidateIDS supplies a complete detached bank to the callback.
func (s *SQLiteStore) MutateCandidateIDS(ctx context.Context, expected Revision, edit func(*Config) error) (Revision, error) {
	return s.mutateCandidate(ctx, expected, edit, true)
}

func (s *SQLiteStore) mutateCandidate(ctx context.Context, expected Revision, edit func(*Config) error, withBank bool) (Revision, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	tx, err := s.beginConfigTx(ctx, &expected)
	if err != nil {
		return "", err
	}
	defer tx.Rollback() //nolint:errcheck
	cfg, err := loadCandidateFrom(ctx, tx, withBank)
	if err != nil {
		return "", err
	}
	if err := edit(cfg); err != nil {
		return "", err
	}
	if !withBank && cfg.IDS.Rules != nil {
		return "", errors.New("bank-free candidate edit supplied IDS rules")
	}
	if withBank && cfg.IDS.Rules == nil {
		cfg.IDS.Rules = []IDSRule{}
	}
	if err := s.saveKindTx(ctx, tx, configKeyCandidate, cfg); err != nil {
		return "", err
	}
	return s.commitRevisionTx(ctx, tx)
}

// SaveCandidate retains an omitted bank; an explicit empty bank clears it.
func (s *SQLiteStore) SaveCandidate(ctx context.Context, expected Revision, cfg *Config) (Revision, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	tx, err := s.beginConfigTx(ctx, &expected)
	if err != nil {
		return "", err
	}
	defer tx.Rollback() //nolint:errcheck
	if err := s.saveKindTx(ctx, tx, configKeyCandidate, cfg); err != nil {
		return "", err
	}
	return s.commitRevisionTx(ctx, tx)
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
	if err := persistOrderedPolicyTx(ctx, tx, key, cfg); err != nil {
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
func (s *SQLiteStore) promoteLocked(ctx context.Context, expected *Revision, ttl time.Duration, capture func(*sql.Tx) error) (Revision, error) {
	tx, err := s.beginConfigTx(ctx, expected)
	if err != nil {
		return "", err
	}
	defer tx.Rollback() //nolint:errcheck
	if capture != nil {
		if err := capture(tx); err != nil {
			return "", err
		}
	}

	candidate, err := loadCandidateFrom(ctx, tx, true)
	if err != nil {
		return "", err
	}
	if err := s.ValidateConfig(candidate); err != nil {
		return "", err
	}
	if err := s.validateSSHAccessLocked(ctx, candidate); err != nil {
		return "", err
	}
	running, err := readKindFrom(ctx, tx, configKeyRunning, false)
	if err != nil && !errors.Is(err, ErrNotFound) {
		return "", err
	}
	if candidate.scopeMigration != nil || candidate.modeMigration != nil || candidate.orderMigration != nil {
		if err := writeConfigTx(ctx, tx, configKeyCandidate, candidate); err != nil {
			return "", err
		}
	}
	runningID, err := bankReference(ctx, tx, configKeyRunning)
	if err != nil {
		return "", err
	}
	candidateID, err := bankReference(ctx, tx, configKeyCandidate)
	if err != nil {
		return "", err
	}
	if candidateID == 0 {
		candidateID = runningID
	}
	if running != nil {
		if err := writeReferencedConfigTx(ctx, tx, configKeyPrevious, running, runningID); err != nil {
			return "", err
		}
	}
	if candidateID != runningID {
		if err := replaceIDSRulesTx(ctx, tx, candidate.IDS.Rules); err != nil {
			return "", err
		}
	}
	if err := writeReferencedConfigTx(ctx, tx, configKeyRunning, candidate, candidateID); err != nil {
		return "", err
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM configs WHERE key IN (?, ?, ?)`, configKeyCandidate, configKeyPending, bootFaultKey); err != nil {
		return "", err
	}
	if ttl > 0 {
		blob, err := json.Marshal(pendingCommit{DeadlineUnix: time.Now().Add(ttl).UnixNano()})
		if err != nil {
			return "", err
		}
		if _, err := tx.ExecContext(ctx, `REPLACE INTO configs (key, data, updated_at) VALUES (?, ?, ?)`, configKeyPending, string(blob), time.Now().Unix()); err != nil {
			return "", err
		}
	}
	revision, err := s.commitRevisionTx(ctx, tx)
	if err != nil {
		return "", err
	}
	s.stopPendingTimerLocked()
	if ttl > 0 {
		s.schedulePendingLocked(ttl)
	}
	return revision, nil
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

func (s *SQLiteStore) rollbackLocked(ctx context.Context, expected *Revision, capture func(*sql.Tx) error) (Revision, error) {
	tx, err := s.beginConfigTx(ctx, expected)
	if err != nil {
		return "", err
	}
	defer tx.Rollback() //nolint:errcheck
	if capture != nil {
		if err := capture(tx); err != nil {
			return "", err
		}
	}

	prev, err := loadKindFrom(ctx, tx, configKeyPrevious)
	if err != nil {
		return "", err
	}
	if err := s.ValidateConfig(prev); err != nil {
		return "", err
	}
	if prev.scopeMigration != nil || prev.modeMigration != nil || prev.orderMigration != nil {
		if err := writeConfigTx(ctx, tx, configKeyPrevious, prev); err != nil {
			return "", err
		}
	}

	id, err := bankReference(ctx, tx, configKeyPrevious)
	if err != nil {
		return "", err
	}
	if id == 0 {
		return "", errors.New("previous snapshot has no IDS bank reference")
	}
	runningID, err := bankReference(ctx, tx, configKeyRunning)
	if err != nil {
		return "", err
	}
	if runningID != id {
		if err := replaceIDSRulesTx(ctx, tx, prev.IDS.Rules); err != nil {
			return "", err
		}
	}
	if err := writeReferencedConfigTx(ctx, tx, configKeyRunning, prev, id); err != nil {
		return "", err
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM configs WHERE key IN (?, ?)`, configKeyPending, bootFaultKey); err != nil {
		return "", err
	}
	revision, err := s.commitRevisionTx(ctx, tx)
	if err != nil {
		return "", err
	}
	s.stopPendingTimerLocked()
	return revision, nil
}

func (s *SQLiteStore) stopPendingTimerLocked() {
	if s.pendingTimer != nil {
		s.pendingTimer.Stop()
		s.pendingTimer = nil
	}
}
