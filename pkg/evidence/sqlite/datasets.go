// SPDX-License-Identifier: Apache-2.0

package sqlite

import (
	"context"
	"crypto/rand"
	"database/sql"

	"github.com/tonylturner/containd/pkg/dp/learn"
	"github.com/tonylturner/containd/pkg/evidence"
)

func saveDataset(ctx context.Context, tx *sql.Tx, d evidence.Dataset) error {
	b, err := encode(d)
	if err != nil {
		return err
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO datasets VALUES(?,?,?,?,?) ON CONFLICT(id) DO UPDATE SET state=excluded.state,data=excluded.data`, d.ID, d.CreatedAt.UnixNano(), d.ExpiresAt.UnixNano(), d.State, b)
	return err
}

func saveWatch(ctx context.Context, tx *sql.Tx, w evidence.Watch) error {
	b, err := encode(w)
	if err != nil {
		return err
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO watches VALUES(?,?,?) ON CONFLICT(id) DO UPDATE SET data=excluded.data`, w.ID, w.DatasetID, b)
	return err
}

func (s *Store) create(ctx context.Context, tx *sql.Tx, d evidence.Dataset) (evidence.Dataset, error) {
	if d.ID == "" || (d.Source != evidence.SourceLive && d.Source != evidence.SourcePCAP) || d.DecoderVersion == "" || d.ProfileFingerprint == "" || d.SnapshotFingerprint == "" {
		return d, ErrConflict
	}
	prior, err := read[evidence.Dataset](ctx, tx, `SELECT data FROM datasets WHERE id=?`, d.ID)
	if err == nil {
		// Never turn a duplicate source into an extended evidence lease.
		if prior.CaptureSHA256 != d.CaptureSHA256 || prior.DecoderVersion != d.DecoderVersion || prior.ProfileFingerprint != d.ProfileFingerprint || prior.SnapshotFingerprint != d.SnapshotFingerprint || prior.Source != d.Source {
			return d, ErrConflict
		}
		return prior, nil
	}
	if err != ErrNotFound {
		return d, err
	}
	var tombstone int
	if err := tx.QueryRowContext(ctx, `SELECT count(*) FROM tombstones WHERE id=?`, d.ID).Scan(&tombstone); err != nil {
		return d, err
	}
	if tombstone != 0 {
		return d, learn.ErrExpired
	}
	d.SchemaVersion, d.CreatedAt = evidence.SchemaVersion, s.now().UTC()
	d.ExpiresAt, d.Records, d.Bytes = d.CreatedAt.Add(evidence.Retention), 0, 0
	d.SealedAt, d.Gaps = nil, []string{}
	d.Losses = nil
	d.State = evidence.DatasetImporting
	if d.Source == evidence.SourceLive {
		d.State = evidence.DatasetCollecting
	}
	b, err := encode(d)
	if err != nil {
		return d, err
	}
	if err := s.fit(ctx, tx, d.ID, uint64(len(b))+2048, 0, 1); err != nil {
		return d, err
	}
	return d, saveDataset(ctx, tx, d)
}

func (s *Store) CreateDataset(ctx context.Context, d evidence.Dataset) (evidence.Dataset, error) {
	if d.Source != evidence.SourcePCAP {
		return d, ErrConflict
	}
	id, err := evidence.ImportID(d)
	if err != nil {
		return d, err
	}
	if d.ID != "" && d.ID != id {
		return d, ErrConflict
	}
	d.ID = id
	err = s.write(ctx, func(tx *sql.Tx) error {
		var err error
		d, err = s.create(ctx, tx, d)
		return err
	})
	return d, err
}

func (s *Store) seal(ctx context.Context, tx *sql.Tx, d evidence.Dataset) error {
	if d.State == evidence.DatasetSealed {
		return nil
	}
	parents, err := allParents(ctx, tx, d.ID)
	if err != nil {
		return err
	}
	d.EvidenceDigest, err = evidence.EvidenceDigest(parents)
	if err != nil {
		return err
	}
	now := s.now().UTC()
	d.SealedAt, d.State = &now, evidence.DatasetSealed
	return saveDataset(ctx, tx, d)
}

func allParents(ctx context.Context, db reader, id string) ([]evidence.Observation, error) {
	var parents []evidence.Observation
	p := evidence.PageRequest{Limit: 200}
	for {
		batch, next, err := page[evidence.Observation](ctx, db, `SELECT id,data FROM parents WHERE dataset=? AND id>? ORDER BY id LIMIT ?`, []any{id}, p)
		if err != nil {
			return nil, err
		}
		parents = append(parents, batch...)
		if next == "" {
			return parents, nil
		}
		p.Cursor = next
	}
}

func (s *Store) GetDataset(ctx context.Context, id string) (evidence.Dataset, error) {
	d, err := s.dataset(ctx, s.db, id)
	if err == nil && d.State == evidence.DatasetImporting {
		return evidence.Dataset{}, ErrNotFound
	}
	return d, err
}

func (s *Store) dataset(ctx context.Context, db reader, id string) (evidence.Dataset, error) {
	d, err := read[evidence.Dataset](ctx, db, `SELECT data FROM datasets WHERE id=?`, id)
	if err == ErrNotFound {
		err = s.missingFrom(ctx, db, id)
	}
	if err == nil && !s.now().Before(d.ExpiresAt) {
		err = learn.ErrExpired
	}
	return d, err
}

func (s *Store) ListDatasets(ctx context.Context, p evidence.PageRequest) (evidence.DatasetPage, error) {
	items, next, err := page[evidence.Dataset](ctx, s.db, `SELECT id,data FROM datasets WHERE state='sealed' AND expires>? AND id>? ORDER BY id LIMIT ?`, []any{s.now().UnixNano()}, p)
	return evidence.DatasetPage{Items: items, NextCursor: next}, err
}

func (s *Store) ListObservations(ctx context.Context, id string, p evidence.PageRequest) (evidence.ObservationPage, error) {
	d, err := s.GetDataset(ctx, id)
	if err != nil {
		return evidence.ObservationPage{}, err
	}
	if d.State != evidence.DatasetSealed {
		return evidence.ObservationPage{}, ErrConflict
	}
	items, next, err := page[evidence.Observation](ctx, s.db, `SELECT id,data FROM parents WHERE dataset=? AND id>? ORDER BY id LIMIT ?`, []any{id}, p)
	return evidence.ObservationPage{Items: items, NextCursor: next}, err
}

func (s *Store) DeleteDataset(ctx context.Context, id string) error {
	return s.write(ctx, func(tx *sql.Tx) error {
		d, err := s.dataset(ctx, tx, id)
		if err != nil {
			return err
		}
		if d.State != evidence.DatasetSealed {
			return ErrConflict
		}
		if err := deleteDataset(ctx, tx, id, false, s.now().Add(evidence.Retention).UnixNano()); err != nil {
			return err
		}
		// An explicit removal of a failed/interrupted capture is permission
		// to retry that source. Automatic expiry/eviction keeps tombstones.
		// Suggestion tombstones remain: deleted proofs are never resurrected.
		if d.Source == evidence.SourcePCAP && len(d.Gaps) > 0 {
			_, err = tx.ExecContext(ctx, `DELETE FROM tombstones WHERE id=?`, id)
		}
		return err
	})
}

func (s *Store) StartWatch(ctx context.Context, req evidence.StartWatchRequest) (evidence.Watch, error) {
	duration, err := req.Duration()
	if err != nil {
		return evidence.Watch{}, err
	}
	if s.watchMetadata == nil {
		return evidence.Watch{}, ErrConflict
	}
	metadata, err := s.watchMetadata()
	if err != nil {
		return evidence.Watch{}, err
	}
	var w evidence.Watch
	err = s.write(ctx, func(tx *sql.Tx) error {
		var active int
		if err := tx.QueryRowContext(ctx, `SELECT count(*) FROM datasets WHERE state='collecting'`).Scan(&active); err != nil {
			return err
		}
		if active != 0 {
			return ErrConflict
		}
		id := rand.Text()
		metadata.ID, metadata.Source = id, evidence.SourceLive
		metadata.CaptureSHA256 = ""
		d, err := s.create(ctx, tx, metadata)
		if err != nil {
			return err
		}
		w = evidence.Watch{ID: id, DatasetID: d.ID, StartedAt: d.CreatedAt, Deadline: d.CreatedAt.Add(duration)}
		return saveWatch(ctx, tx, w)
	})
	return w, err
}

func (s *Store) stop(ctx context.Context, tx *sql.Tx, w evidence.Watch, reason string) (evidence.Watch, error) {
	if w.StoppedAt != nil {
		return w, nil
	}
	now := s.now().UTC()
	w.StoppedAt, w.StopReason = &now, reason
	if err := saveWatch(ctx, tx, w); err != nil {
		return w, err
	}
	d, err := read[evidence.Dataset](ctx, tx, `SELECT data FROM datasets WHERE id=?`, w.DatasetID)
	if err != nil {
		return w, err
	}
	if reason == "restart" {
		// Wall-clock lease bounds cannot delimit capture timestamps after
		// a clock step or capture lag. No durable packet checkpoint exists.
		d.RecordLoss(evidence.CollectionLoss{Code: "watch_restart"})
	} else if reason == "policy_changed" {
		d.RecordLoss(evidence.CollectionLoss{Code: "policy_changed"})
	}
	return w, s.seal(ctx, tx, d)
}

func (s *Store) StopWatch(ctx context.Context, id string) (evidence.Watch, error) {
	return s.StopWatchReason(ctx, id, "")
}

// StopWatchReason seals an explicit lease after its collector has drained.
func (s *Store) StopWatchReason(ctx context.Context, id, reason string) (evidence.Watch, error) {
	if reason != "" && reason != "policy_changed" {
		return evidence.Watch{}, ErrConflict
	}
	var w evidence.Watch
	err := s.write(ctx, func(tx *sql.Tx) error {
		var err error
		w, err = s.watch(ctx, tx, id)
		if err != nil {
			return err
		}
		stopReason := reason
		if stopReason == "" {
			stopReason = "operator"
			if !s.now().Before(w.Deadline) {
				stopReason = "deadline"
			}
		}
		w, err = s.stop(ctx, tx, w, stopReason)
		return err
	})
	return w, err
}

func (s *Store) GetWatch(ctx context.Context, id string) (evidence.Watch, error) {
	return s.watch(ctx, s.db, id)
}
func (s *Store) watch(ctx context.Context, db reader, id string) (evidence.Watch, error) {
	w, err := read[evidence.Watch](ctx, db, `SELECT data FROM watches WHERE id=?`, id)
	if err == ErrNotFound {
		err = s.missingFrom(ctx, db, id)
	}
	if err == nil {
		_, err = s.dataset(ctx, db, w.DatasetID)
	}
	return w, err
}

func (s *Store) ListWatches(ctx context.Context, p evidence.PageRequest) (evidence.WatchPage, error) {
	items, next, err := page[evidence.Watch](ctx, s.db, `SELECT w.id,w.data FROM watches w JOIN datasets d ON d.id=w.dataset WHERE d.expires>? AND w.id>? ORDER BY w.id LIMIT ?`, []any{s.now().UnixNano()}, p)
	return evidence.WatchPage{Items: items, NextCursor: next}, err
}

func (s *Store) stopRestartedWatches(ctx context.Context, tx *sql.Tx) error {
	watches, _, err := page[evidence.Watch](ctx, tx, `SELECT w.id,w.data FROM watches w JOIN datasets d ON d.id=w.dataset WHERE d.state='collecting' AND w.id>? ORDER BY w.id LIMIT ?`, nil, evidence.PageRequest{Limit: 200})
	if err != nil {
		return err
	}
	for _, w := range watches {
		if _, err := s.stop(ctx, tx, w, "restart"); err != nil {
			return err
		}
	}
	return nil
}

func (s *Store) recover(ctx context.Context) error {
	return s.write(ctx, func(tx *sql.Tx) error {
		if err := s.invalidateProofs(ctx, tx); err != nil {
			return err
		}
		if err := s.stopRestartedWatches(ctx, tx); err != nil {
			return err
		}
		datasets, _, err := page[evidence.Dataset](ctx, tx, `SELECT id,data FROM datasets WHERE state='importing' AND id>? ORDER BY id LIMIT ?`, nil, evidence.PageRequest{Limit: 200})
		if err != nil {
			return err
		}
		for _, d := range datasets {
			d.RecordLoss(evidence.CollectionLoss{Code: "interrupted_import"})
			if err := s.seal(ctx, tx, d); err != nil {
				return err
			}
		}
		return nil
	})
}

// ActiveWatch is a detached lease read used by the bounded collection worker.
func (s *Store) ActiveWatch(ctx context.Context) (evidence.Watch, error) {
	w, err := read[evidence.Watch](ctx, s.db, `SELECT w.data FROM watches w JOIN datasets d ON d.id=w.dataset WHERE d.state='collecting'`)
	if err == nil && (w.StoppedAt != nil || !s.now().Before(w.Deadline)) {
		err = ErrNotFound
	}
	return w, err
}

func (s *Store) missingFrom(ctx context.Context, db reader, id string) error {
	var n int
	err := db.QueryRowContext(ctx, `SELECT count(*) FROM tombstones WHERE id=? AND expires>?`, id, s.now().UnixNano()).Scan(&n)
	if err != nil {
		return err
	}
	if n != 0 {
		return learn.ErrExpired
	}
	return ErrNotFound
}
