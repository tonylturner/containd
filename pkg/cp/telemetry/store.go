// SPDX-License-Identifier: Apache-2.0

package telemetry

import (
	"context"
	"database/sql"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"maps"
	"os"
	"path/filepath"
	"sync"
	"time"

	wire "github.com/tonylturner/containd/pkg/common/telemetry"
	_ "modernc.org/sqlite"
)

const schemaVersion = 1

const SeriesLimit = 320
const BudgetBytes int64 = 64 << 20
const reclaimBytes int64 = 60 << 20

type Store struct {
	observedInterval bool
	mu               sync.Mutex
	db               *sql.DB
	path             string
	state            wire.CollectorState
	admitted         map[string]bool
	budget           int64
	reclaim          int64
}

type row struct {
	sample  wire.CounterSample
	point   wire.Point
	missing bool
}

// Open opens a dedicated history file. Failure must not prevent management
// from serving its other APIs.
func Open(path string) (*Store, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return nil, err
	}
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)
	var version, tables int
	if err = db.QueryRow("PRAGMA user_version").Scan(&version); err != nil {
		db.Close()
		return nil, err
	}
	if version == 0 {
		if err = db.QueryRow("SELECT count(*) FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'").Scan(&tables); err != nil {
			db.Close()
			return nil, err
		}
	}
	if err = checkSchema(version, tables); err != nil {
		db.Close()
		return nil, err
	}
	s := &Store{db: db, path: path, state: wire.CollectorState{State: "running"}, budget: BudgetBytes, reclaim: reclaimBytes}
	if _, err = db.Exec(`PRAGMA page_size=4096; PRAGMA auto_vacuum=INCREMENTAL; PRAGMA journal_mode=WAL; PRAGMA synchronous=NORMAL; PRAGMA busy_timeout=5000; PRAGMA cache_spill=OFF; PRAGMA wal_autocheckpoint=0;
 CREATE TABLE IF NOT EXISTS series(id INTEGER PRIMARY KEY, key TEXT NOT NULL UNIQUE, metric TEXT NOT NULL, origin TEXT NOT NULL, dims TEXT NOT NULL, last INTEGER NOT NULL);
 CREATE TABLE IF NOT EXISTS buckets(series INTEGER NOT NULL, resolution INTEGER NOT NULL, t INTEGER NOT NULL, v BLOB, d INTEGER NOT NULL, q INTEGER NOT NULL, PRIMARY KEY(series,resolution,t)) WITHOUT ROWID;
 CREATE INDEX IF NOT EXISTS bucket_age ON buckets(resolution,t);
 CREATE TABLE IF NOT EXISTS coverage(metric TEXT PRIMARY KEY, covered INTEGER NOT NULL, active INTEGER NOT NULL) WITHOUT ROWID;
 CREATE TABLE IF NOT EXISTS floors(resolution INTEGER PRIMARY KEY, t INTEGER NOT NULL) WITHOUT ROWID; PRAGMA user_version=1;`); err != nil {
		db.Close()
		return nil, err
	}
	// Reserve a whole-database WAL, including frame overhead. With spilling
	// disabled each dirty page is appended at most once at commit. This bounds
	// even a retention transaction that deletes almost the entire database.
	const maxPages = (BudgetBytes - (1 << 20)) / 2 / 4096
	var pageSize, pages int64
	if err = db.QueryRow("PRAGMA page_size").Scan(&pageSize); err != nil || pageSize != 4096 {
		db.Close()
		return nil, fmt.Errorf("telemetry requires 4096-byte pages: %d: %v", pageSize, err)
	}
	if err = db.QueryRow("PRAGMA max_page_count=8064").Scan(&pages); err != nil || pages != maxPages {
		db.Close()
		return nil, fmt.Errorf("telemetry database exceeds physical admission limit: %d: %v", pages, err)
	}
	if err = s.maintain(context.Background()); err != nil {
		db.Close()
		return nil, err
	}
	if s.admitted, err = seriesKeys(context.Background(), db); err != nil {
		db.Close()
		return nil, err
	}

	return s, nil
}

func seriesKeys(ctx context.Context, q interface {
	QueryContext(context.Context, string, ...any) (*sql.Rows, error)
}) (map[string]bool, error) {
	rows, err := q.QueryContext(ctx, "SELECT key FROM series")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	keys := map[string]bool{}
	for rows.Next() {
		var key string
		if err = rows.Scan(&key); err != nil {
			return nil, err
		}
		keys[key] = true
	}
	if len(keys) > SeriesLimit {
		return nil, fmt.Errorf("telemetry series limit exceeded")
	}
	return keys, rows.Err()
}

func (s *Store) admittedKeys() map[string]bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return maps.Clone(s.admitted)
}

func checkSchema(version, tables int) error {
	if version != schemaVersion && (version != 0 || tables != 0) {
		return fmt.Errorf("unsupported telemetry schema %d", version)
	}
	return nil
}

func (s *Store) Close() error { s.mu.Lock(); defer s.mu.Unlock(); return s.db.Close() }
func (s *Store) State() wire.CollectorState {
	s.mu.Lock()
	defer s.mu.Unlock()
	state := s.state
	state.Unavailable = cloneUnavailable(state.Unavailable)
	return state
}

func cloneUnavailable(entries []wire.SourceUnavailable) []wire.SourceUnavailable {
	var out []wire.SourceUnavailable
	for _, entry := range entries {
		entry.Dims = maps.Clone(entry.Dims)
		out = append(out, entry)
	}
	return out
}

func (s *Store) fail(err error) error {
	s.state.State = "stalled"
	s.state.Error = err.Error()
	return err
}

// write persists admission, buckets, roll-ups, retention and coverage atomically.
// Only the sampler calls this; readers never trigger maintenance.
func (s *Store) write(ctx context.Context, now time.Time, rows []row) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.maintain(ctx); err != nil {
		return s.fail(err)
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return s.fail(err)
	}
	defer func() { _ = tx.Rollback() }()
	if _, err = tx.ExecContext(ctx, `DELETE FROM buckets WHERE series IN (SELECT id FROM series WHERE last<?); DELETE FROM series WHERE last<?`, now.Add(-30*24*time.Hour).Unix(), now.Add(-30*24*time.Hour).Unix()); err != nil {
		return s.fail(err)
	}
	admitted, err := seriesKeys(ctx, tx)
	if err != nil {
		return s.fail(err)
	}
	count := len(admitted)

	observedInterval := false
	var dropped uint64
	for _, r := range rows {
		sample := r.sample
		if sample.Origin != wire.OriginDemo && r.point.Q == wire.QualityObserved {
			observedInterval = true
		}
		if sample.Origin == "" {
			sample.Origin = wire.OriginReal
		}
		key := identity(sample)
		var id int64
		err = tx.QueryRowContext(ctx, "SELECT id FROM series WHERE key=?", key).Scan(&id)
		if err == sql.ErrNoRows {
			if r.missing {
				continue
			}
			if count >= SeriesLimit {
				dropped++
				continue
			}
			b, _ := json.Marshal(sample.Dims)
			result, e := tx.ExecContext(ctx, "INSERT INTO series(key,metric,origin,dims,last) VALUES(?,?,?,?,?)", key, sample.Metric, sample.Origin, string(b), now.Unix())
			if e != nil {
				return s.fail(e)
			}
			id, err = result.LastInsertId()
			if err != nil {
				return s.fail(err)
			}
			count++
			admitted[key] = true
		} else if err != nil {
			return s.fail(err)
		} else if !r.missing {
			if _, err = tx.ExecContext(ctx, "UPDATE series SET last=? WHERE id=?", now.Unix(), id); err != nil {
				return s.fail(err)
			}
		}
		if r.point.T.IsZero() {
			continue
		} // baseline only
		storedPoint, err := putDelta(ctx, tx, id, r.point)
		if err != nil {
			return s.fail(err)
		}
		if err = roll(ctx, tx, id, 10, 60, r.point.T); err != nil {
			return s.fail(err)
		}
		if err = roll(ctx, tx, id, 60, 900, r.point.T); err != nil {
			return s.fail(err)
		}
		if sample.Origin == wire.OriginReal && storedPoint.V != nil {
			covered, active := 0, 0
			if storedPoint.Q == wire.QualityObserved {
				covered = 1
			}
			if *storedPoint.V > 0 {
				active = 1
			}
			if _, err = tx.ExecContext(ctx, `INSERT INTO coverage VALUES(?,?,?) ON CONFLICT(metric) DO UPDATE SET covered=max(covered,excluded.covered),active=max(active,excluded.active)`, sample.Metric, covered, active); err != nil {
				return s.fail(err)
			}
		}
	}
	for resolution, retention := range map[int]time.Duration{10: time.Hour, 60: 24 * time.Hour, 900: 30 * 24 * time.Hour} {
		floor := now.Truncate(time.Duration(resolution) * time.Second).Add(-retention).Unix()
		if _, err = tx.ExecContext(ctx, "DELETE FROM buckets WHERE resolution=? AND t<?", resolution, floor); err != nil {
			return s.fail(err)
		}
		if _, err = tx.ExecContext(ctx, `INSERT INTO floors VALUES(?,?) ON CONFLICT(resolution) DO UPDATE SET t=max(t,excluded.t)`, resolution, floor); err != nil {
			return s.fail(err)
		}
	}
	if err = tx.Commit(); err != nil {
		return s.fail(err)
	}
	s.observedInterval = s.observedInterval || observedInterval
	s.admitted = admitted
	s.state.DroppedSeries += dropped
	if err = s.maintain(ctx); err != nil {
		return s.fail(err)
	}
	s.state.State = "running"
	s.state.Error = ""
	s.state.LastSampleAt = now
	return nil
}

// putDelta preserves disjoint sampled intervals attributed to the same bucket
// (for example a spanning scrape followed by an aligned scrape). Roll-ups use
// replacement upserts instead, since they recompute authoritative children.
func putDelta(ctx context.Context, tx *sql.Tx, id int64, p wire.Point) (wire.Point, error) {
	existing, err := readPoints(ctx, tx, id, 10, p.T, p.T.Add(Resolution))
	if err != nil {
		return p, err
	}
	if old, ok := existing[p.T.Unix()]; ok && old.V != nil {
		if p.V == nil {
			p = old
			if p.Q != wire.QualityReset {
				p.Q = wire.QualityPartial
			}
		} else {
			combined, e := Combine([]wire.Point{old, p}, true, p.T)
			if e != nil {
				return p, e
			}
			p = combined
			if p.Q != wire.QualityReset {
				p.Q = wire.QualityPartial
			}
		}
	}
	return p, put(ctx, tx, id, 10, p)
}

func put(ctx context.Context, tx *sql.Tx, id int64, res int, p wire.Point) error {
	var value any
	if p.V != nil {
		value = binary.AppendUvarint(nil, *p.V)
	}
	code := -1
	for i, q := range qualities {
		if q == p.Q {
			code = i
			break
		}
	}
	if code < 0 {
		return fmt.Errorf("invalid telemetry quality %q", p.Q)
	}
	_, err := tx.ExecContext(ctx, `INSERT INTO buckets VALUES(?,?,?,?,?,?) ON CONFLICT(series,resolution,t) DO UPDATE SET v=excluded.v,d=excluded.d,q=excluded.q`, id, res, p.T.Unix(), value, p.D, code)
	return err
}

var qualities = [...]wire.Quality{wire.QualityGap, wire.QualityObserved, wire.QualityPartial, wire.QualityReset}

func readPoints(ctx context.Context, q interface {
	QueryContext(context.Context, string, ...any) (*sql.Rows, error)
}, id int64, res int, from, to time.Time) (map[int64]wire.Point, error) {
	rows, err := q.QueryContext(ctx, "SELECT t,v,d,q FROM buckets WHERE series=? AND resolution=? AND t>=? AND t<?", id, res, from.Unix(), to.Unix())
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[int64]wire.Point{}
	for rows.Next() {
		var ts int64
		var value []byte
		var code int
		var p wire.Point
		if err = rows.Scan(&ts, &value, &p.D, &code); err != nil {
			return nil, err
		}
		p.T = time.Unix(ts, 0).UTC()
		if code < 0 || code >= len(qualities) {
			return nil, fmt.Errorf("invalid stored telemetry quality %d", code)
		}
		p.Q = qualities[code]
		if value != nil {
			n, read := binary.Uvarint(value)
			if read <= 0 || read != len(value) {
				return nil, fmt.Errorf("invalid stored telemetry counter")
			}
			p.V = &n
		}

		out[ts] = p
	}
	return out, rows.Err()
}

func roll(ctx context.Context, tx *sql.Tx, id int64, fine, coarse int, t time.Time) error {
	start := t.Truncate(time.Duration(coarse) * time.Second)
	points, err := readPoints(ctx, tx, id, fine, start, start.Add(time.Duration(coarse)*time.Second))
	if err != nil {
		return err
	}
	children := make([]wire.Point, 0, coarse/fine)
	for offset := 0; offset < coarse; offset += fine {
		ts := start.Add(time.Duration(offset) * time.Second)
		p, ok := points[ts.Unix()]
		if !ok {
			p = wire.Point{T: ts, Q: wire.QualityGap}
		}
		children = append(children, p)
	}
	p, err := Combine(children, true, start)
	if err != nil {
		return err
	}
	return put(ctx, tx, id, coarse, p)
}
