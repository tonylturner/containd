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
	MutateCandidate(ctx context.Context, edit func(*Config) error) error
	Commit(ctx context.Context) error
	CommitConfirmed(ctx context.Context, ttl time.Duration) error
	ConfirmCommit(ctx context.Context) error
	Rollback(ctx context.Context) error

	// Running IDS rules retain a separate engine-consumer table. All config
	// states reference immutable banks; Load returns the complete snapshot.
	SaveIDSRules(ctx context.Context, rules []IDSRule) error
	LoadIDSRules(ctx context.Context) ([]IDSRule, error)

	Close() error
}

// SQLiteStore persists configuration in a SQLite database file.
type SQLiteStore struct {
	db                 *sql.DB
	mu                 sync.Mutex
	pendingTimer       *time.Timer
	autoRollbackNotify chan<- struct{}
	options            storeOptions
	recoveryHoldsBanks bool // protected by mu; saved apply rows may still need their banks

	// SSH callbacks are protected by mu.
	sshAccessValidator     func(context.Context, SSHConfig) error
	sshRuntimePolicyReader func(context.Context) (SSHRuntimePolicy, error)
}

// SetAutoRollbackNotify registers a best-effort notification after a successful
// timed rollback. Sends never block, even while the store mutex is held.
// The receiver owns the channel and must not close it; nil unregisters it.
// Rollbacks before registration are covered by management's boot replay.
func (s *SQLiteStore) SetAutoRollbackNotify(notify chan<- struct{}) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.autoRollbackNotify = notify
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
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin wipe tx: %w", err)
	}
	defer tx.Rollback() //nolint:errcheck
	if err := wipeAllTx(ctx, tx); err != nil {
		return err
	}
	if err := s.commitStateTx(ctx, tx); err != nil {
		return err
	}
	s.stopPendingTimerLocked()
	return nil
}

// NewSQLiteStore opens or creates a SQLite database at the given path.
func NewSQLiteStore(path string, opts ...StoreOption) (*SQLiteStore, error) {
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
	for _, opt := range opts {
		opt(&store.options)
	}
	if err := store.upgradeSnapshots(context.Background()); err != nil {
		db.Close()
		return nil, err
	}
	if err := store.extractBanks(context.Background()); err != nil {
		db.Close()
		return nil, err
	}
	if _, err := store.MigrateIndustrialScope(context.Background()); err != nil {
		db.Close()
		return nil, err
	}
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
		`CREATE TABLE IF NOT EXISTS ids_banks (id INTEGER PRIMARY KEY AUTOINCREMENT, data TEXT NOT NULL);`,
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

// Save validates and writes running only, retaining an omitted IDS bank.
// Candidate, previous and pending state are untouched. Boot repairs must use
// Repair instead; callers replacing everything must explicitly WipeAll first.
func (s *SQLiteStore) Save(ctx context.Context, cfg *Config) error {
	if cfg == nil {
		return errors.New("config is nil")
	}
	if err := s.ValidateConfig(cfg); err != nil {
		return err
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin save tx: %w", err)
	}
	defer tx.Rollback() //nolint:errcheck

	if cfg.IDS.Rules != nil {
		if err := replaceChangedIDSRulesTx(ctx, tx, cfg.IDS.Rules); err != nil {
			return err
		}
	}
	if err := writeConfigTx(ctx, tx, configKeyRunning, cfg); err != nil {
		return err
	}
	return s.commitStateTx(ctx, tx)
}

func (s *SQLiteStore) saveKind(ctx context.Context, kind string, cfg *Config) error {
	if cfg == nil {
		return errors.New("config is nil")
	}
	if err := s.ValidateConfig(cfg); err != nil {
		return err
	}
	if err := s.validateSSHAccessLocked(ctx, cfg); err != nil {
		return err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback() //nolint:errcheck
	if err := writeConfigTx(ctx, tx, kind, cfg); err != nil {
		return err
	}
	return s.commitStateTx(ctx, tx)
}

// Load returns a consistent running configuration including its IDS bank.
func (s *SQLiteStore) Load(ctx context.Context) (*Config, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.loadRunningLocked(ctx)
}

func (s *SQLiteStore) loadRunningLocked(ctx context.Context) (*Config, error) {
	return loadRunningFrom(ctx, s.db)
}

type configReader interface {
	QueryContext(context.Context, string, ...any) (*sql.Rows, error)
	QueryRowContext(context.Context, string, ...any) *sql.Row
}

func loadRunningFrom(ctx context.Context, db configReader) (*Config, error) {
	return loadKindFrom(ctx, db, configKeyRunning)
}

func (s *SQLiteStore) loadKind(ctx context.Context, kind string) (*Config, error) {
	return loadKindFrom(ctx, s.db, kind)
}

func loadKindFrom(ctx context.Context, db configReader, kind string) (*Config, error) {
	return readKindFrom(ctx, db, kind, true)
}

func readKindFrom(ctx context.Context, db configReader, kind string, withBank bool) (*Config, error) {
	cfg, err := readKindUnupgradedFrom(ctx, db, kind, withBank)
	if err != nil {
		return nil, err
	}
	if err := UpgradeInPlace(cfg); err != nil {
		return nil, err
	}
	NormalizeLegacySSHShellMode(cfg)
	return cfg, nil
}

func readKindUnupgradedFrom(ctx context.Context, db configReader, kind string, withBank bool) (*Config, error) {
	row := db.QueryRowContext(ctx, `SELECT data FROM configs WHERE key = ?`, kind)
	var raw string
	if err := row.Scan(&raw); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("load config: %w", err)
	}
	var stored storedConfig
	if err := json.Unmarshal([]byte(raw), &stored); err != nil {
		return nil, fmt.Errorf("unmarshal config: %w", err)
	}
	cfg := stored.Config
	if !withBank {
		cfg.IDS.Rules = nil
		return &cfg, nil
	}
	if stored.BankID != 0 {
		rules, err := loadBankFrom(ctx, db, stored.BankID)
		cfg.IDS.Rules = rules
		return &cfg, err
	}
	if kind == configKeyCandidate || kind == configKeyPrevious {
		switch stored.SnapshotFormat {
		case snapshotFormatBankUnchanged:
			running, err := loadRunningFrom(ctx, db)
			if err != nil {
				return nil, err
			}
			cfg.IDS.Rules = running.IDS.Rules
		case snapshotFormatEmbeddedBank:
			// Even an omitted/empty rules field is an authoritative empty bank.
		default:
			return nil, fmt.Errorf("unsupported snapshot format %d", stored.SnapshotFormat)
		}
	}
	return &cfg, nil
}

// Commit promotes the candidate and cancels any pending confirmed commit.
func (s *SQLiteStore) Commit(ctx context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.promoteLocked(ctx, 0)
}

type pendingCommit struct {
	DeadlineUnix int64 `json:"deadline_unix"`
}

// CommitConfirmed promotes the candidate and schedules transactional rollback.
func (s *SQLiteStore) CommitConfirmed(ctx context.Context, ttl time.Duration) error {
	if ttl <= 0 {
		return errors.New("ttl must be > 0")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.promoteLocked(ctx, ttl)
}

// ConfirmCommit cancels any pending auto-rollback from CommitConfirmed.
func (s *SQLiteStore) ConfirmCommit(ctx context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	cfg, err := s.loadRunningLocked(ctx)
	if err != nil {
		return err
	}
	if err := s.ValidateConfig(cfg); err != nil {
		return err
	}
	return s.clearPendingLocked(ctx)
}

// Rollback restores the previous running config if available.
func (s *SQLiteStore) Rollback(ctx context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.rollbackLocked(ctx)
}

// Close releases database resources.
func (s *SQLiteStore) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.pendingTimer != nil {
		s.pendingTimer.Stop()
		s.pendingTimer = nil
	}
	s.autoRollbackNotify = nil
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
		applied, err := s.timedRollbackLocked(bg)
		if err != nil {
			slog.Error("auto-rollback failed", "error", err)
			return
		}
		if !applied {
			return
		}
		select {
		case s.autoRollbackNotify <- struct{}{}:
		default:
		}
	})
}

// SaveIDSRules replaces all stored IDS rules.
func (s *SQLiteStore) SaveIDSRules(ctx context.Context, rules []IDSRule) error {
	if err := validateIDS(IDSConfig{Rules: rules}); err != nil {
		return err
	}
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
	cfg, err := readKindFrom(ctx, tx, configKeyRunning, false)
	if err != nil && !errors.Is(err, ErrNotFound) {
		return err
	}
	if cfg != nil {
		cfg.IDS.Rules = rules
		if cfg.IDS.Rules == nil {
			cfg.IDS.Rules = []IDSRule{}
		}
		if err := writeConfigTx(ctx, tx, configKeyRunning, cfg); err != nil {
			return err
		}
	}
	return s.commitStateTx(ctx, tx)
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

// LoadIDSRules reads the running bank without migrating or writing on reads.
func (s *SQLiteStore) LoadIDSRules(ctx context.Context) ([]IDSRule, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.loadIDSRulesRaw(ctx)
}

func (s *SQLiteStore) loadIDSRulesRaw(ctx context.Context) ([]IDSRule, error) {
	return loadIDSRulesFrom(ctx, s.db)
}

func loadIDSRulesFrom(ctx context.Context, db interface {
	QueryContext(context.Context, string, ...any) (*sql.Rows, error)
}) ([]IDSRule, error) {
	rows, err := db.QueryContext(ctx, `SELECT data FROM ids_rules ORDER BY id`)
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
		if _, err := s.timedRollbackLocked(ctx); err != nil {
			return err
		}
		return s.clearPendingLocked(ctx)
	}
	s.schedulePendingLocked(time.Until(deadline))
	return nil
}
