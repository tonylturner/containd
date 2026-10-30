// SPDX-License-Identifier: Apache-2.0

// Package sqlite implements the engine-owned, bounded evidence authority.
package sqlite

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/tonylturner/containd/pkg/dp/learn"
	"github.com/tonylturner/containd/pkg/evidence"
	_ "modernc.org/sqlite"
)

var (
	ErrNotFound = errors.New("evidence not found")
	ErrConflict = errors.New("evidence conflict")
	ErrBudget   = errors.New("evidence budget exceeded")
)

const (
	maxPhysical = 256 << 20
	maxBatch    = 1 << 20
)

// Options permit a deterministic clock and smaller admission budgets in tests.
// Zero fields use the production hard limit; larger limits are refused.
type Options struct {
	Now     func() time.Time
	Budgets evidence.Budgets
	// WatchMetadata snapshots the active decoder, profile and policy identities
	// at explicit start. The store cannot invent runtime fingerprints.
	WatchMetadata func() (evidence.Dataset, error)
	// CompatibleProof is supplied by the evaluator/generator owner. Evidence
	// survives upgrades, but proof compatibility must never be guessed.
	CompatibleProof func(learn.Versions) bool
}

type Store struct {
	db              *sql.DB
	mu              sync.Mutex
	now             func() time.Time
	limits          evidence.Budgets
	path            string
	watchMetadata   func() (evidence.Dataset, error)
	compatibleProof func(learn.Versions) bool
}

var _ learn.SuggestionStore = (*Store)(nil)

func Open(path string, opts Options) (*Store, error) {
	if opts.CompatibleProof == nil {
		return nil, fmt.Errorf("evidence store requires an explicit proof compatibility policy")
	}
	limits := evidence.Budgets{MaxBytes: 128 << 20, MaxRecords: 100000, MaxDatasets: 32, MaxParentBytes: 256 << 10, MaxParentObjects: 4096}
	requested := []*uint64{&opts.Budgets.MaxBytes, &opts.Budgets.MaxRecords, &opts.Budgets.MaxDatasets, &opts.Budgets.MaxParentBytes}
	hard := []uint64{limits.MaxBytes, limits.MaxRecords, limits.MaxDatasets, limits.MaxParentBytes}
	for i, p := range requested {
		if *p > hard[i] {
			return nil, ErrBudget
		}
		if *p == 0 {
			*p = hard[i]
		}
	}
	if opts.Budgets.MaxParentObjects > limits.MaxParentObjects {
		return nil, ErrBudget
	}
	if opts.Budgets.MaxParentObjects == 0 {
		opts.Budgets.MaxParentObjects = limits.MaxParentObjects
	}
	if opts.Now == nil {
		opts.Now = time.Now
	}
	if path == "" {
		return nil, fmt.Errorf("evidence database path is required")
	}
	// Pass a filesystem path, never a SQLite URI or an in-memory DSN.
	absolute, err := filepath.Abs(path)
	if err != nil {
		return nil, err
	}
	path = absolute
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return nil, err
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return nil, err
	}
	if err := f.Chmod(0600); err != nil {
		_ = f.Close()
		return nil, err
	}
	if err := f.Close(); err != nil {
		return nil, err
	}
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)
	s := &Store{db: db, now: opts.Now, limits: opts.Budgets, path: path, watchMetadata: opts.WatchMetadata, compatibleProof: opts.CompatibleProof}
	for _, stmt := range []string{
		`PRAGMA page_size=4096`,
		`PRAGMA journal_mode=WAL`, `PRAGMA synchronous=NORMAL`,
		`PRAGMA busy_timeout=5000`, `PRAGMA foreign_keys=ON`,
		`PRAGMA recursive_triggers=ON`,
		`PRAGMA journal_size_limit=4194304`, `PRAGMA wal_autocheckpoint=128`,
		// Do not spill pages repeatedly while evicting a whole dataset. With
		// one connection, a checkpoint before each write and at most 120 MiB
		// of dirty pages, DB + WAL + SHM stays below the 256 MiB ceiling.
		`PRAGMA cache_spill=OFF`,
	} {
		if _, err := db.Exec(stmt); err != nil {
			_ = db.Close()
			return nil, err
		}
	}
	var pageSize int64
	if err := db.QueryRow(`PRAGMA page_size`).Scan(&pageSize); err != nil {
		_ = db.Close()
		return nil, err
	}
	if pageSize != 4096 {
		_ = db.Close()
		return nil, fmt.Errorf("unsupported evidence page size %d", pageSize)
	}
	var actualMax int64
	if err := db.QueryRow(`PRAGMA max_page_count=30720`).Scan(&actualMax); err != nil {
		_ = db.Close()
		return nil, err
	}
	if actualMax != 30720 {
		_ = db.Close()
		return nil, ErrBudget
	}
	if err := s.migrate(); err != nil {
		_ = db.Close()
		return nil, err
	}
	if err := s.recover(context.Background()); err != nil {
		_ = db.Close()
		return nil, err
	}
	return s, nil
}

func (s *Store) migrate() error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	if _, err := tx.Exec(`CREATE TABLE IF NOT EXISTS schema_meta(version INTEGER NOT NULL)`); err != nil {
		return err
	}
	var version int
	err = tx.QueryRow(`SELECT version FROM schema_meta`).Scan(&version)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return err
	}
	if version > 1 {
		return fmt.Errorf("unsupported evidence schema %d", version)
	}
	if version == 0 {
		_, err = tx.Exec(`
CREATE TABLE datasets(id TEXT PRIMARY KEY, created INTEGER NOT NULL, expires INTEGER NOT NULL, state TEXT NOT NULL, data BLOB NOT NULL);
CREATE INDEX datasets_expiry ON datasets(expires);
CREATE TABLE watches(id TEXT PRIMARY KEY, dataset TEXT NOT NULL REFERENCES datasets(id) ON DELETE CASCADE, data BLOB NOT NULL);
CREATE TABLE parents(id TEXT PRIMARY KEY, dataset TEXT NOT NULL REFERENCES datasets(id) ON DELETE CASCADE, expires INTEGER NOT NULL, data BLOB NOT NULL);
CREATE INDEX parents_dataset ON parents(dataset,id);
CREATE INDEX parents_expiry ON parents(expires,dataset);
CREATE TABLE suggestions(id TEXT PRIMARY KEY, dataset TEXT NOT NULL REFERENCES datasets(id) ON DELETE CASCADE, expires INTEGER NOT NULL, data BLOB NOT NULL);
CREATE INDEX suggestions_dataset ON suggestions(dataset,id);
CREATE TABLE stage_requests(id TEXT PRIMARY KEY, expires INTEGER NOT NULL, request BLOB NOT NULL, resolved BLOB NOT NULL, completed INTEGER NOT NULL DEFAULT 0);
CREATE TABLE stage_selections(request TEXT NOT NULL REFERENCES stage_requests(id) ON DELETE CASCADE, suggestion TEXT PRIMARY KEY REFERENCES suggestions(id) ON DELETE CASCADE);
CREATE TABLE withheld(parent TEXT NOT NULL REFERENCES parents(id) ON DELETE CASCADE, version TEXT NOT NULL, reason TEXT NOT NULL, PRIMARY KEY(parent,version,reason));
CREATE TABLE tombstones(id TEXT PRIMARY KEY, expires INTEGER NOT NULL);
CREATE TABLE counters(id INTEGER PRIMARY KEY CHECK(id=1), data BLOB NOT NULL);
CREATE TABLE usage(id INTEGER PRIMARY KEY CHECK(id=1), records INTEGER NOT NULL, bytes INTEGER NOT NULL, datasets INTEGER NOT NULL);
INSERT INTO usage VALUES(1,0,0,0);
INSERT INTO schema_meta VALUES(1);`)
		if err != nil {
			return err
		}
		if err := createUsageTriggers(tx); err != nil {
			return err
		}
		if _, err := tx.Exec(`INSERT INTO counters VALUES(1,'{"withheld":{}}')`); err != nil {
			return err
		}
	}
	return tx.Commit()
}

// All identifiers and expressions here are schema literals, never caller input.
// Updating gauges in SQLite avoids rescanning 100,000 parents for each admission
// and accounts for proof/review/receipt growth in the same transaction.
func createUsageTriggers(tx *sql.Tx) error {
	for _, table := range []struct {
		name, size        string
		records, datasets int
	}{
		{"datasets", "length(data)", 0, 1},
		{"watches", "length(data)", 0, 0},
		{"parents", "length(data)", 1, 0},
		{"suggestions", "length(data)", 0, 0},
		{"stage_requests", "length(request)+length(resolved)", 0, 0},
		{"stage_selections", "length(request)+length(suggestion)", 0, 0},
		{"counters", "length(data)", 0, 0},
		{"tombstones", "length(id)+16", 0, 0},
		{"withheld", "length(parent)+length(version)+length(reason)", 0, 0},
	} {
		qualify := func(prefix string) string {
			return strings.ReplaceAll(table.size, "length(", "length("+prefix+".")
		}
		statements := []string{
			fmt.Sprintf(`CREATE TRIGGER %s_usage_insert AFTER INSERT ON %s BEGIN UPDATE usage SET records=records+%d,bytes=bytes+(%s),datasets=datasets+%d WHERE id=1; END`, table.name, table.name, table.records, qualify("NEW"), table.datasets),
			fmt.Sprintf(`CREATE TRIGGER %s_usage_delete AFTER DELETE ON %s BEGIN UPDATE usage SET records=records-%d,bytes=bytes-(%s),datasets=datasets-%d WHERE id=1; END`, table.name, table.name, table.records, qualify("OLD"), table.datasets),
			fmt.Sprintf(`CREATE TRIGGER %s_usage_update AFTER UPDATE ON %s BEGIN UPDATE usage SET bytes=bytes+(%s)-(%s) WHERE id=1; END`, table.name, table.name, qualify("NEW"), qualify("OLD")),
		}
		for _, statement := range statements {
			if _, err := tx.Exec(statement); err != nil {
				return err
			}
		}
	}
	return nil
}

func encode(v any) ([]byte, error) { return json.Marshal(v) }

type reader interface {
	QueryRowContext(context.Context, string, ...any) *sql.Row
	QueryContext(context.Context, string, ...any) (*sql.Rows, error)
}

func read[T any](ctx context.Context, db reader, query string, args ...any) (T, error) {
	var out T
	var b []byte
	if err := db.QueryRowContext(ctx, query, args...).Scan(&b); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			err = ErrNotFound
		}
		return out, err
	}
	err := json.Unmarshal(b, &out)
	return out, err
}

func page[T any](ctx context.Context, db reader, query string, args []any, p evidence.PageRequest) ([]T, string, error) {
	if p.Limit == 0 {
		p.Limit = 200
	}
	if p.Limit < 1 || p.Limit > 200 || len(p.Cursor) > 256 {
		return nil, "", ErrConflict
	}
	args = append(args, p.Cursor, p.Limit+1)
	rows, err := db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, "", err
	}
	defer func() { _ = rows.Close() }()
	out := []T{}
	last := ""
	for rows.Next() {
		var id string
		var b []byte
		if err := rows.Scan(&id, &b); err != nil {
			return nil, "", err
		}
		if len(out) == p.Limit {
			return out, last, rows.Err()
		}
		var v T
		if err := json.Unmarshal(b, &v); err != nil {
			return nil, "", err
		}
		out, last = append(out, v), id
	}
	return out, "", rows.Err()
}

func (s *Store) write(ctx context.Context, fn func(*sql.Tx) error) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.checkpoint(ctx); err != nil {
		return err
	}
	if err := s.physicalBudget(); err != nil {
		return err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	if err := s.expire(ctx, tx); err != nil {
		return err
	}
	if err := fn(tx); err != nil {
		return err
	}
	records, bytes, datasets, err := gauges(ctx, tx)
	if err != nil {
		return err
	}
	// Admission sites choose what may be evicted. Never evict the very
	// evidence just resolved/certified as a side effect of saving its proof.
	if records > s.limits.MaxRecords || bytes > s.limits.MaxBytes || datasets > s.limits.MaxDatasets {
		return ErrBudget
	}
	return tx.Commit()
}

func (s *Store) physicalBudget() error {
	var size int64
	for _, suffix := range []string{"", "-wal", "-shm"} {
		info, err := os.Stat(s.path + suffix)
		if err == nil {
			size += info.Size()
		} else if !errors.Is(err, os.ErrNotExist) {
			return err
		}
	}
	// A write transaction can use at most 1 MiB of parent input, with 8 MiB
	// reserved for indexes, counters and checkpoint overhead.
	if size > maxPhysical-(8<<20) {
		return ErrBudget
	}
	return nil
}

func (s *Store) Close() error { return s.db.Close() }

// Maintain is called by the engine worker, never implicitly starts collection.
func (s *Store) Maintain(ctx context.Context) error {
	if err := s.write(ctx, func(tx *sql.Tx) error { return s.stopDue(ctx, tx, false) }); err != nil {
		return err
	}
	return s.checkpoint(ctx)
}

func (s *Store) checkpoint(ctx context.Context) error {
	var busy, log, checkpointed int
	if err := s.db.QueryRowContext(ctx, `PRAGMA wal_checkpoint(TRUNCATE)`).Scan(&busy, &log, &checkpointed); err != nil {
		return err
	}
	if busy != 0 || log != 0 {
		return fmt.Errorf("evidence checkpoint blocked: busy=%d log=%d checkpointed=%d", busy, log, checkpointed)
	}
	return nil
}
