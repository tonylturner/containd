// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

package audit

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	_ "modernc.org/sqlite"
)

// Store persists audit records.
type Store interface {
	Add(ctx context.Context, r Record) error
	List(ctx context.Context, limit int, offset ...int) ([]Record, error)
	Close() error
}

type SQLiteStore struct {
	db *sql.DB
}

// WipeAll deletes all persisted audit records.
func (s *SQLiteStore) WipeAll(ctx context.Context) error {
	if s == nil || s.db == nil {
		return fmt.Errorf("audit store unavailable")
	}
	if _, err := s.db.ExecContext(ctx, `DELETE FROM audit_records`); err != nil {
		return fmt.Errorf("wipe audit records: %w", err)
	}
	return nil
}

func NewSQLiteStore(path string) (*SQLiteStore, error) {
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, fmt.Errorf("open audit sqlite: %w", err)
	}
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)
	if err := tuneSQLite(db); err != nil {
		db.Close()
		return nil, err
	}
	if err := bootstrap(db); err != nil {
		db.Close()
		return nil, err
	}
	return &SQLiteStore{db: db}, nil
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

func bootstrap(db *sql.DB) error {
	schema := `
CREATE TABLE IF NOT EXISTS audit_records (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  ts INTEGER NOT NULL,
  actor TEXT,
  source TEXT,
  action TEXT,
  target TEXT,
  result TEXT,
  detail TEXT
);
`
	if _, err := db.Exec(schema); err != nil {
		return fmt.Errorf("create audit schema: %w", err)
	}
	return nil
}

func (s *SQLiteStore) Add(ctx context.Context, r Record) error {
	if r.Timestamp.IsZero() {
		r.Timestamp = time.Now().UTC()
	}
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO audit_records (ts, actor, source, action, target, result, detail) VALUES (?, ?, ?, ?, ?, ?, ?)`,
		r.Timestamp.Unix(), r.Actor, r.Source, r.Action, r.Target, r.Result, r.Detail)
	if err != nil {
		return fmt.Errorf("insert audit record: %w", err)
	}
	return nil
}

func (s *SQLiteStore) List(ctx context.Context, limit int, offset ...int) ([]Record, error) {
	if limit <= 0 {
		limit = 100
	}
	off := 0
	if len(offset) > 0 && offset[0] > 0 {
		off = offset[0]
	}
	rows, err := s.db.QueryContext(ctx, `SELECT id, ts, actor, source, action, target, result, detail FROM audit_records ORDER BY id DESC LIMIT ? OFFSET ?`, limit, off)
	if err != nil {
		return nil, fmt.Errorf("query audit records: %w", err)
	}
	defer rows.Close()

	var out []Record
	for rows.Next() {
		var rec Record
		var ts int64
		if err := rows.Scan(&rec.ID, &ts, &rec.Actor, &rec.Source, &rec.Action, &rec.Target, &rec.Result, &rec.Detail); err != nil {
			return nil, fmt.Errorf("scan audit record: %w", err)
		}
		rec.Timestamp = time.Unix(ts, 0).UTC()
		out = append(out, rec)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate audit records: %w", err)
	}
	return out, nil
}

func (s *SQLiteStore) Close() error {
	if s.db != nil {
		return s.db.Close()
	}
	return nil
}
