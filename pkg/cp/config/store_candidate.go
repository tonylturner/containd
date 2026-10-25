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
	cfg, err := s.loadKind(ctx, configKeyCandidate)
	if errors.Is(err, ErrNotFound) {
		return s.loadRunningLocked(ctx)
	}
	return cfg, err
}

// MutateCandidate serializes read, edit, validation and persistence with all
// other candidate mutations and promotions. The callback must not call Store.
func (s *SQLiteStore) MutateCandidate(ctx context.Context, edit func(*Config) error) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	cfg, err := s.loadCandidateLocked(ctx)
	if err != nil {
		return err
	}
	if err := edit(cfg); err != nil {
		return err
	}
	return s.saveKind(ctx, configKeyCandidate, cfg)
}

// SaveCandidate replaces desired config while retaining an omitted IDS bank.
// An explicitly supplied empty bank clears the candidate rules.
func (s *SQLiteStore) SaveCandidate(ctx context.Context, cfg *Config) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if cfg == nil {
		return errors.New("config is nil")
	}
	next := cloneConfigForPersist(cfg)
	if cfg.IDS.Rules == nil {
		existing, err := s.loadCandidateLocked(ctx)
		if err != nil && !errors.Is(err, ErrNotFound) {
			return err
		}
		if existing != nil {
			next.IDS.Rules = existing.IDS.Rules
		}
	}
	return s.saveKind(ctx, configKeyCandidate, next)
}

func writeConfigTx(ctx context.Context, tx *sql.Tx, key string, cfg *Config) error {
	blob, err := marshalStoredConfig(key, cfg)
	if err != nil {
		return err
	}
	_, err = tx.ExecContext(ctx, `REPLACE INTO configs (key, data, updated_at) VALUES (?, ?, ?)`, key, string(blob), time.Now().Unix())
	return err
}

// Candidate and previous blobs embed their complete IDS banks. Running keeps
// the bank in ids_rules for engine consumers. Both representations change in
// the same transaction; no secondary candidate/previous tables are needed.
func (s *SQLiteStore) promoteLocked(ctx context.Context, ttl time.Duration) error {
	candidate, err := s.loadCandidateLocked(ctx)
	if err != nil {
		return err
	}
	if err := s.ValidateConfig(candidate); err != nil {
		return err
	}
	running, err := s.loadRunningLocked(ctx)
	if err != nil && !errors.Is(err, ErrNotFound) {
		return err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback() //nolint:errcheck
	if running != nil {
		if err := writeConfigTx(ctx, tx, configKeyPrevious, running); err != nil {
			return err
		}
	}
	if err := writeRunningTx(ctx, tx, candidate); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM configs WHERE key IN (?, ?)`, configKeyCandidate, configKeyPending); err != nil {
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
	if err := tx.Commit(); err != nil {
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
	persisted := cloneConfigForPersist(cfg)
	persisted.IDS.Rules = nil
	return writeConfigTx(ctx, tx, configKeyRunning, persisted)
}

func (s *SQLiteStore) rollbackLocked(ctx context.Context) error {
	prev, err := s.loadKind(ctx, configKeyPrevious)
	if err != nil {
		return err
	}
	if err := s.ValidateConfig(prev); err != nil {
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
	if err := writeRunningTx(ctx, tx, prev); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM configs WHERE key = ?`, configKeyPending); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
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
