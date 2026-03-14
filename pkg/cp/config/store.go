// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

package config

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"time"

	_ "modernc.org/sqlite"
)

var (
	// ErrNotFound is returned when no config has been persisted yet.
	ErrNotFound = errors.New("config not found")
)

const (
	configKeyRunning   = "running"
	configKeyCandidate = "candidate"
	configKeyPrevious  = "previous"
	configKeyPending   = "commit_confirmed_pending"
)

// Store defines persistence operations for the control-plane config.
type Store interface {
	Save(ctx context.Context, cfg *Config) error
	Load(ctx context.Context) (*Config, error)
	SaveCandidate(ctx context.Context, cfg *Config) error
	LoadCandidate(ctx context.Context) (*Config, error)
	Commit(ctx context.Context) error
	CommitConfirmed(ctx context.Context, ttl time.Duration) error
	ConfirmCommit(ctx context.Context) error
	Rollback(ctx context.Context) error

	// IDS rules are stored separately from the config to avoid bloating
	// the config blob with potentially thousands of imported rules.
	SaveIDSRules(ctx context.Context, rules []IDSRule) error
	LoadIDSRules(ctx context.Context) ([]IDSRule, error)

	Close() error
}

// SQLiteStore persists configuration in a SQLite database file.
type SQLiteStore struct {
	db           *sql.DB
	mu           sync.Mutex
	pendingTimer *time.Timer
}

// WipeAll deletes all persisted config state (running/candidate/previous/pending)
// plus separately stored IDS rules.
// It does not close the DB or change schema.
func (s *SQLiteStore) WipeAll(ctx context.Context) error {
	if s == nil || s.db == nil {
		return errors.New("config store unavailable")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.pendingTimer != nil {
		s.pendingTimer.Stop()
		s.pendingTimer = nil
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin wipe tx: %w", err)
	}
	defer tx.Rollback() //nolint:errcheck
	if _, err := tx.ExecContext(ctx, `DELETE FROM configs`); err != nil {
		return fmt.Errorf("wipe configs: %w", err)
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM ids_rules`); err != nil {
		return fmt.Errorf("wipe ids_rules: %w", err)
	}
	return tx.Commit()
}

// NewSQLiteStore opens or creates a SQLite database at the given path.
func NewSQLiteStore(path string) (*SQLiteStore, error) {
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, fmt.Errorf("open sqlite: %w", err)
	}
	// Keep access serialized; this avoids SQLITE_BUSY errors with modernc/sqlite
	// when multiple goroutines update candidate/running state concurrently.
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)
	if err := tuneSQLite(db); err != nil {
		db.Close()
		return nil, err
	}
	if err := bootstrapSchema(db); err != nil {
		db.Close()
		return nil, err
	}
	store := &SQLiteStore{db: db}
	if err := store.checkAndSchedulePending(); err != nil {
		db.Close()
		return nil, err
	}
	return store, nil
}

func tuneSQLite(db *sql.DB) error {
	pragmas := []string{
		`PRAGMA journal_mode=WAL;`,
		`PRAGMA synchronous=NORMAL;`,
		`PRAGMA busy_timeout=5000;`,
	}
	for _, p := range pragmas {
		if _, err := db.Exec(p); err != nil {
			return fmt.Errorf("sqlite pragma %q: %w", p, err)
		}
	}
	return nil
}

func bootstrapSchema(db *sql.DB) error {
	stmts := []string{
		`CREATE TABLE IF NOT EXISTS configs (
  key TEXT PRIMARY KEY,
  data TEXT NOT NULL,
  updated_at INTEGER NOT NULL
);`,
		`CREATE TABLE IF NOT EXISTS ids_rules (
  id TEXT PRIMARY KEY,
  data TEXT NOT NULL,
  updated_at INTEGER NOT NULL
);`,
	}
	for _, stmt := range stmts {
		if _, err := db.Exec(stmt); err != nil {
			return fmt.Errorf("create schema: %w", err)
		}
	}
	return nil
}

// Save validates and writes the config as the running config.
// It also clears any stale candidate so that LoadCandidate will re-seed
// from the updated running config, keeping the two in sync.
func (s *SQLiteStore) Save(ctx context.Context, cfg *Config) error {
	if cfg == nil {
		return errors.New("config is nil")
	}
	if err := cfg.Validate(); err != nil {
		return fmt.Errorf("config validation failed: %w", err)
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	persisted := cloneConfigForPersist(cfg)
	replaceIDSRules := cfg.IDS.Rules != nil
	if replaceIDSRules {
		persisted.IDS.Rules = nil
	}
	blob, err := json.Marshal(persisted)
	if err != nil {
		return fmt.Errorf("marshal config: %w", err)
	}

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin save tx: %w", err)
	}
	defer tx.Rollback() //nolint:errcheck

	if replaceIDSRules {
		if err := replaceIDSRulesTx(ctx, tx, cfg.IDS.Rules); err != nil {
			return err
		}
	}
	if _, err := tx.ExecContext(ctx, `REPLACE INTO configs (key, data, updated_at) VALUES (?, ?, ?)`, configKeyRunning, string(blob), time.Now().Unix()); err != nil {
		return fmt.Errorf("persist config: %w", err)
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM configs WHERE key = ?`, configKeyCandidate); err != nil {
		return fmt.Errorf("clear candidate: %w", err)
	}
	return tx.Commit()
}

// SaveCandidate stores a candidate config (staged).
func (s *SQLiteStore) SaveCandidate(ctx context.Context, cfg *Config) error {
	return s.saveKind(ctx, configKeyCandidate, cfg)
}

func (s *SQLiteStore) saveKind(ctx context.Context, kind string, cfg *Config) error {
	if cfg == nil {
		return errors.New("config is nil")
	}
	if err := cfg.Validate(); err != nil {
		return fmt.Errorf("config validation failed: %w", err)
	}
	blob, err := json.Marshal(cfg)
	if err != nil {
		return fmt.Errorf("marshal config: %w", err)
	}
	_, err = s.db.ExecContext(ctx, `REPLACE INTO configs (key, data, updated_at) VALUES (?, ?, ?)`, kind, string(blob), time.Now().Unix())
	if err != nil {
		return fmt.Errorf("persist config: %w", err)
	}
	return nil
}

func cloneConfigForPersist(cfg *Config) *Config {
	if cfg == nil {
		return nil
	}
	cp := *cfg
	if cfg.IDS.Rules != nil {
		cp.IDS.Rules = append([]IDSRule(nil), cfg.IDS.Rules...)
	}
	return &cp
}

// Load returns the running config or ErrNotFound if none exists.
func (s *SQLiteStore) Load(ctx context.Context) (*Config, error) {
	return s.loadKind(ctx, configKeyRunning)
}

// LoadCandidate returns the candidate config or ErrNotFound if none exists.
func (s *SQLiteStore) LoadCandidate(ctx context.Context) (*Config, error) {
	cfg, err := s.loadKind(ctx, configKeyCandidate)
	if err == nil {
		return cfg, nil
	}
	if !errors.Is(err, ErrNotFound) {
		return nil, err
	}

	// Appliance UX: treat "candidate missing" as "candidate == running" and
	// lazily seed candidate so operations like `diff` and `commit` behave
	// predictably on fresh installs.
	running, rerr := s.Load(ctx)
	if rerr != nil {
		return nil, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	// Double-check after acquiring the lock.
	if existing, eerr := s.loadKind(ctx, configKeyCandidate); eerr == nil {
		return existing, nil
	}
	_ = s.saveKind(ctx, configKeyCandidate, running)
	return running, nil
}

func (s *SQLiteStore) loadKind(ctx context.Context, kind string) (*Config, error) {
	row := s.db.QueryRowContext(ctx, `SELECT data FROM configs WHERE key = ?`, kind)
	var raw string
	if err := row.Scan(&raw); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("load config: %w", err)
	}
	var cfg Config
	if err := json.Unmarshal([]byte(raw), &cfg); err != nil {
		return nil, fmt.Errorf("unmarshal config: %w", err)
	}
	if err := UpgradeInPlace(&cfg); err != nil {
		return nil, err
	}
	return &cfg, nil
}

// Commit promotes candidate to running and stores previous running for rollback.
func (s *SQLiteStore) Commit(ctx context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	candidate, err := s.LoadCandidate(ctx)
	if err != nil {
		return fmt.Errorf("load candidate: %w", err)
	}
	if running, err := s.Load(ctx); err == nil {
		if err := s.saveKind(ctx, configKeyPrevious, running); err != nil {
			return fmt.Errorf("save previous: %w", err)
		}
	}
	if err := s.saveKind(ctx, configKeyRunning, candidate); err != nil {
		return fmt.Errorf("promote candidate: %w", err)
	}
	_, _ = s.db.ExecContext(ctx, `DELETE FROM configs WHERE key = ?`, configKeyCandidate)
	_ = s.clearPendingLocked(ctx)
	return nil
}

type pendingCommit struct {
	DeadlineUnix int64 `json:"deadline_unix"`
}

// CommitConfirmed commits candidate to running and schedules auto-rollback unless confirmed.
func (s *SQLiteStore) CommitConfirmed(ctx context.Context, ttl time.Duration) error {
	if ttl <= 0 {
		return errors.New("ttl must be > 0")
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	candidate, err := s.LoadCandidate(ctx)
	if err != nil {
		return fmt.Errorf("load candidate: %w", err)
	}
	if running, err := s.Load(ctx); err == nil {
		if err := s.saveKind(ctx, configKeyPrevious, running); err != nil {
			return fmt.Errorf("save previous: %w", err)
		}
	}
	if err := s.saveKind(ctx, configKeyRunning, candidate); err != nil {
		return fmt.Errorf("promote candidate: %w", err)
	}
	_, _ = s.db.ExecContext(ctx, `DELETE FROM configs WHERE key = ?`, configKeyCandidate)

	pending := pendingCommit{DeadlineUnix: time.Now().Add(ttl).UnixNano()}
	blob, _ := json.Marshal(pending)
	if _, err := s.db.ExecContext(ctx, `REPLACE INTO configs (key, data, updated_at) VALUES (?, ?, ?)`, configKeyPending, string(blob), time.Now().Unix()); err != nil {
		return fmt.Errorf("persist pending commit: %w", err)
	}
	s.schedulePendingLocked(ttl)
	return nil
}

// ConfirmCommit cancels any pending auto-rollback from CommitConfirmed.
func (s *SQLiteStore) ConfirmCommit(ctx context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	_ = s.clearPendingLocked(ctx)
	return nil
}

// Rollback restores the previous running config if available.
func (s *SQLiteStore) Rollback(ctx context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	prev, err := s.loadKind(ctx, configKeyPrevious)
	if err != nil {
		return fmt.Errorf("load previous: %w", err)
	}
	if err := s.saveKind(ctx, configKeyRunning, prev); err != nil {
		return fmt.Errorf("restore previous: %w", err)
	}
	_ = s.clearPendingLocked(ctx)
	return nil
}

// Close releases database resources.
func (s *SQLiteStore) Close() error {
	if s.db != nil {
		return s.db.Close()
	}
	return nil
}

func (s *SQLiteStore) loadPending(ctx context.Context) (*pendingCommit, error) {
	row := s.db.QueryRowContext(ctx, `SELECT data FROM configs WHERE key = ?`, configKeyPending)
	var raw string
	if err := row.Scan(&raw); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	var pending pendingCommit
	if err := json.Unmarshal([]byte(raw), &pending); err != nil {
		return nil, err
	}
	return &pending, nil
}

func (s *SQLiteStore) clearPendingLocked(ctx context.Context) error {
	if s.pendingTimer != nil {
		s.pendingTimer.Stop()
		s.pendingTimer = nil
	}
	_, err := s.db.ExecContext(ctx, `DELETE FROM configs WHERE key = ?`, configKeyPending)
	if err != nil {
		return err
	}
	return nil
}

func (s *SQLiteStore) schedulePendingLocked(after time.Duration) {
	if s.pendingTimer != nil {
		s.pendingTimer.Stop()
	}
	s.pendingTimer = time.AfterFunc(after, func() {
		// Re-check pending state before rollback.
		bg := context.Background()
		s.mu.Lock()
		defer s.mu.Unlock()
		pending, err := s.loadPending(bg)
		if err != nil || pending == nil {
			return
		}
		if time.Now().UnixNano() < pending.DeadlineUnix {
			remain := time.Until(time.Unix(0, pending.DeadlineUnix))
			s.schedulePendingLocked(remain)
			return
		}
		if err := s.rollbackLocked(bg); err != nil {
			slog.Error("auto-rollback failed", "error", err)
			return
		}
		_ = s.clearPendingLocked(bg)
	})
}

func (s *SQLiteStore) rollbackLocked(ctx context.Context) error {
	prev, err := s.loadKind(ctx, configKeyPrevious)
	if err != nil {
		return err
	}
	return s.saveKind(ctx, configKeyRunning, prev)
}

// SaveIDSRules replaces all stored IDS rules.
func (s *SQLiteStore) SaveIDSRules(ctx context.Context, rules []IDSRule) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback() //nolint:errcheck

	if err := replaceIDSRulesTx(ctx, tx, rules); err != nil {
		return err
	}
	return tx.Commit()
}

func replaceIDSRulesTx(ctx context.Context, tx *sql.Tx, rules []IDSRule) error {
	if _, err := tx.ExecContext(ctx, `DELETE FROM ids_rules`); err != nil {
		return fmt.Errorf("clear ids_rules: %w", err)
	}
	now := time.Now().Unix()
	stmt, err := tx.PrepareContext(ctx, `INSERT INTO ids_rules (id, data, updated_at) VALUES (?, ?, ?)`)
	if err != nil {
		return fmt.Errorf("prepare ids_rules insert: %w", err)
	}
	defer stmt.Close()

	for _, r := range rules {
		blob, err := json.Marshal(r)
		if err != nil {
			return fmt.Errorf("marshal ids rule %s: %w", r.ID, err)
		}
		if _, err := stmt.ExecContext(ctx, r.ID, string(blob), now); err != nil {
			return fmt.Errorf("insert ids rule %s: %w", r.ID, err)
		}
	}
	return nil
}

// LoadIDSRules returns all stored IDS rules. If the ids_rules table is empty
// but the running config contains legacy embedded rules, they are migrated
// to the separate table automatically.
func (s *SQLiteStore) LoadIDSRules(ctx context.Context) ([]IDSRule, error) {
	rules, err := s.loadIDSRulesRaw(ctx)
	if err != nil {
		return nil, err
	}
	if len(rules) > 0 {
		return rules, nil
	}

	// Migration: check if running config has embedded IDS rules to migrate.
	cfg, err := s.Load(ctx)
	if err != nil {
		if errors.Is(err, ErrNotFound) {
			return nil, nil
		}
		return nil, err
	}
	if len(cfg.IDS.Rules) == 0 {
		return nil, nil
	}
	slog.Info("migrating IDS rules from config to separate storage", "count", len(cfg.IDS.Rules))
	if err := s.SaveIDSRules(ctx, cfg.IDS.Rules); err != nil {
		return nil, fmt.Errorf("migrate ids rules: %w", err)
	}
	// Clear rules from the config blob to avoid duplication.
	cfg.IDS.Rules = nil
	_ = s.saveKind(ctx, configKeyRunning, cfg)
	return s.loadIDSRulesRaw(ctx)
}

func (s *SQLiteStore) loadIDSRulesRaw(ctx context.Context) ([]IDSRule, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT data FROM ids_rules ORDER BY id`)
	if err != nil {
		return nil, fmt.Errorf("query ids_rules: %w", err)
	}
	defer rows.Close()

	var rules []IDSRule
	for rows.Next() {
		var raw string
		if err := rows.Scan(&raw); err != nil {
			return nil, fmt.Errorf("scan ids_rule: %w", err)
		}
		var r IDSRule
		if err := json.Unmarshal([]byte(raw), &r); err != nil {
			return nil, fmt.Errorf("unmarshal ids_rule: %w", err)
		}
		rules = append(rules, r)
	}
	return rules, rows.Err()
}

func (s *SQLiteStore) checkAndSchedulePending() error {
	ctx := context.Background()
	s.mu.Lock()
	defer s.mu.Unlock()
	pending, err := s.loadPending(ctx)
	if err != nil {
		if errors.Is(err, ErrNotFound) {
			return nil
		}
		return err
	}
	deadline := time.Unix(0, pending.DeadlineUnix)
	if time.Now().After(deadline) {
		if err := s.rollbackLocked(ctx); err != nil {
			return err
		}
		return s.clearPendingLocked(ctx)
	}
	s.schedulePendingLocked(time.Until(deadline))
	return nil
}
