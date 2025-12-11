package config

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"

	_ "modernc.org/sqlite"
)

var (
	// ErrNotFound is returned when no config has been persisted yet.
	ErrNotFound = errors.New("config not found")
)

// Store defines persistence operations for the control-plane config.
type Store interface {
	Save(ctx context.Context, cfg *Config) error
	Load(ctx context.Context) (*Config, error)
	Close() error
}

// SQLiteStore persists configuration in a SQLite database file.
type SQLiteStore struct {
	db *sql.DB
}

// NewSQLiteStore opens or creates a SQLite database at the given path.
func NewSQLiteStore(path string) (*SQLiteStore, error) {
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, fmt.Errorf("open sqlite: %w", err)
	}
	if err := bootstrapSchema(db); err != nil {
		db.Close()
		return nil, err
	}
	return &SQLiteStore{db: db}, nil
}

func bootstrapSchema(db *sql.DB) error {
	schema := `
CREATE TABLE IF NOT EXISTS configs (
  id INTEGER PRIMARY KEY CHECK (id = 1),
  data TEXT NOT NULL
);`
	if _, err := db.Exec(schema); err != nil {
		return fmt.Errorf("create schema: %w", err)
	}
	return nil
}

// Save validates and writes the config as a JSON blob.
func (s *SQLiteStore) Save(ctx context.Context, cfg *Config) error {
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
	_, err = s.db.ExecContext(ctx, `REPLACE INTO configs (id, data) VALUES (1, ?)`, string(blob))
	if err != nil {
		return fmt.Errorf("persist config: %w", err)
	}
	return nil
}

// Load returns the persisted config or ErrNotFound if none exists.
func (s *SQLiteStore) Load(ctx context.Context) (*Config, error) {
	row := s.db.QueryRowContext(ctx, `SELECT data FROM configs WHERE id = 1`)
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
	return &cfg, nil
}

// Close releases database resources.
func (s *SQLiteStore) Close() error {
	if s.db != nil {
		return s.db.Close()
	}
	return nil
}
