// SPDX-License-Identifier: Apache-2.0

package sqlite

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"

	"github.com/tonylturner/containd/pkg/evidence"
)

func counters(ctx context.Context, tx reader) (evidence.Counters, error) {
	return read[evidence.Counters](ctx, tx, `SELECT data FROM counters WHERE id=1`)
}

func saveCounters(ctx context.Context, tx *sql.Tx, c evidence.Counters) error {
	b, err := encode(c)
	if err != nil {
		return err
	}
	_, err = tx.ExecContext(ctx, `UPDATE counters SET data=? WHERE id=1`, b)
	return err
}

func gauges(ctx context.Context, tx reader) (records, bytes, datasets uint64, err error) {
	err = tx.QueryRowContext(ctx, `SELECT records,bytes,datasets FROM usage WHERE id=1`).Scan(&records, &bytes, &datasets)
	return
}

func (s *Store) Counters(ctx context.Context) (evidence.Counters, error) {
	// One read transaction keeps gauges and cumulative counters consistent.
	tx, err := s.db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return evidence.Counters{}, err
	}
	defer func() { _ = tx.Rollback() }()
	c, err := counters(ctx, tx)
	if err != nil {
		return c, err
	}
	c.Records, c.Bytes, _, err = gauges(ctx, tx)
	return c, err
}

func deleteDataset(ctx context.Context, tx *sql.Tx, id string, expired bool, tombstoneUntil int64) error {
	var count, bytes uint64
	if err := tx.QueryRowContext(ctx, `SELECT
(SELECT count(*) FROM parents WHERE dataset=?),
(SELECT coalesce(sum(length(data)),0) FROM parents WHERE dataset=?)+
(SELECT coalesce(sum(length(data)),0) FROM suggestions WHERE dataset=?)+
(SELECT coalesce(sum(length(data)),0) FROM watches WHERE dataset=?)+
(SELECT coalesce(sum(length(data)),0) FROM datasets WHERE id=?)`, id, id, id, id, id).Scan(&count, &bytes); err != nil {
		return err
	}
	c, err := counters(ctx, tx)
	if err != nil {
		return err
	}
	if expired {
		c.ExpiredRecords += count
	} else {
		c.EvictedRecords += count
		c.EvictedBytes += bytes
	}
	// Bounded tombstones preserve the expired-vs-unknown HTTP distinction.
	if _, err := tx.ExecContext(ctx, `INSERT OR REPLACE INTO tombstones SELECT id,? FROM suggestions WHERE dataset=?`, tombstoneUntil, id); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `INSERT OR REPLACE INTO tombstones VALUES(?,?)`, id, tombstoneUntil); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM datasets WHERE id=?`, id); err != nil {
		return err
	}
	return saveCounters(ctx, tx, c)
}

func (s *Store) expire(ctx context.Context, tx *sql.Tx) error {
	now := s.now().UTC().UnixNano()
	rows, err := tx.QueryContext(ctx, `SELECT id FROM datasets WHERE expires<=? UNION SELECT dataset FROM parents WHERE expires<=?`, now, now)
	if err != nil {
		return err
	}
	var ids []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			_ = rows.Close()
			return err
		}
		ids = append(ids, id)
	}
	err = rows.Err()
	_ = rows.Close()
	if err != nil {
		return err
	}
	for _, id := range ids {
		if err := deleteDataset(ctx, tx, id, true, s.now().Add(evidence.Retention).UnixNano()); err != nil {
			return err
		}
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM tombstones WHERE expires<=?`, now); err != nil {
		return err
	}
	_, err = tx.ExecContext(ctx, `DELETE FROM stage_requests WHERE expires<=?`, now)
	return err
}

func (s *Store) fit(ctx context.Context, tx *sql.Tx, protected string, addBytes, addRecords, addDatasets uint64) error {
	return s.fitExcept(ctx, tx, []string{protected}, addBytes, addRecords, addDatasets)
}

func (s *Store) fitExcept(ctx context.Context, tx *sql.Tx, protected []string, addBytes, addRecords, addDatasets uint64) error {
	keep := map[string]bool{}
	for _, id := range protected {
		keep[id] = true
	}
	for {
		records, bytes, datasets, err := gauges(ctx, tx)
		if err != nil {
			return err
		}
		physical, err := physicalFits(ctx, tx, addBytes, addRecords, addDatasets)
		if err != nil {
			return err
		}
		if physical && records+addRecords <= s.limits.MaxRecords && bytes+addBytes <= s.limits.MaxBytes && datasets+addDatasets <= s.limits.MaxDatasets {
			return nil
		}
		rows, err := tx.QueryContext(ctx, `SELECT id FROM datasets WHERE state='sealed' ORDER BY created,id`)
		if err != nil {
			return err
		}
		id := ""
		for rows.Next() {
			var candidate string
			if err := rows.Scan(&candidate); err != nil {
				_ = rows.Close()
				return err
			}
			if !keep[candidate] {
				id = candidate
				break
			}
		}
		err = rows.Err()
		_ = rows.Close()
		if err != nil {
			return err
		}
		if id == "" {
			return ErrBudget
		}
		if err := deleteDataset(ctx, tx, id, false, s.now().Add(evidence.Retention).UnixNano()); err != nil {
			return err
		}
	}
}

func (s *Store) Ingest(ctx context.Context, req evidence.IngestRequest) (evidence.IngestResult, error) {
	result := evidence.IngestResult{Reasons: map[evidence.WithheldReason]uint64{}}
	batch, err := json.Marshal(req)
	if err != nil {
		return result, err
	}
	if len(req.Parents) > 128 || len(batch) > maxBatch {
		return result, ErrBudget
	}
	if len(req.Gaps) > 32 || len(req.Losses) > evidence.MaxLosses {
		return result, ErrBudget
	}
	for _, gap := range req.Gaps {
		if gap == "" || len(gap) > 128 {
			return result, ErrBudget
		}
	}
	for _, loss := range req.Losses {
		if loss.Code == "" || len(loss.Code) > 128 || len(loss.ConnectionID) > 4096 {
			return result, ErrBudget
		}
	}
	err = s.write(ctx, func(tx *sql.Tx) error {
		d, err := s.dataset(ctx, tx, req.DatasetID)
		if err != nil {
			return err
		}
		if d.State != evidence.DatasetCollecting && d.State != evidence.DatasetImporting {
			return ErrConflict
		}
		var deadline int64
		if d.Source == evidence.SourceLive {
			if req.Seal {
				return ErrConflict // only StopWatch can stop and seal a lease
			}
			w, err := read[evidence.Watch](ctx, tx, `SELECT data FROM watches WHERE dataset=?`, d.ID)
			if err != nil {
				return err
			}
			if w.StoppedAt != nil {
				return ErrConflict
			}
			deadline = w.Deadline.UnixNano()
		}
		for _, gap := range req.Gaps {
			localized := false
			for _, loss := range req.Losses {
				localized = localized || loss.Code == gap
			}
			if !localized {
				d.RecordLoss(evidence.CollectionLoss{Code: gap})
			}
		}
		for _, loss := range req.Losses {
			d.RecordLoss(loss)
		}
		if req.LostBatches > 0 && len(req.Gaps) == 0 && len(req.Losses) == 0 {
			d.RecordLoss(evidence.CollectionLoss{Code: "collection_loss"})
		}
		if len(d.Gaps) > 32 {
			return ErrBudget
		}
		c, err := counters(ctx, tx)
		if err != nil {
			return err
		}
		c.LostBatches += req.LostBatches
		if c.Withheld == nil {
			c.Withheld = map[evidence.WithheldReason]uint64{}
		}
		// Reserve a conservative upper bound for the whole decoded batch once.
		// Without pressure, avoid repeating SQLite page/gauge queries per parent.
		// Under pressure each parent still follows normal eviction/admission order.
		records, bytes, _, err := gauges(ctx, tx)
		if err != nil {
			return err
		}
		reserve := uint64(len(batch)) + uint64(len(req.Parents))*4096
		batchHeadroom, err := physicalFits(ctx, tx, reserve, uint64(len(req.Parents)), 0)
		if err != nil {
			return err
		}
		batchHeadroom = batchHeadroom && records+uint64(len(req.Parents)) <= s.limits.MaxRecords && bytes+reserve <= s.limits.MaxBytes
		for _, parent := range req.Parents {
			collected := req.CollectedAt
			if collected.IsZero() {
				collected = s.now()
			}
			if deadline != 0 && (collected.UnixNano() > deadline || parent.CapturedAt.UnixNano() > deadline) {
				result.Rejected++
				c.RejectedParents++
				result.Reasons[evidence.WithheldExpired]++
				c.Withheld[evidence.WithheldExpired]++
				// Traffic outside the lease is not a loss inside the dataset.
				continue
			}
			if parent.DatasetID != d.ID || parent.Source != d.Source {
				return ErrConflict
			}
			if err := parent.ValidateEnvelope(); err != nil {
				return err
			}
			if parent.DecoderVersion != d.DecoderVersion || parent.ProfileFingerprint != d.ProfileFingerprint || parent.SnapshotFingerprint != d.SnapshotFingerprint {
				return ErrConflict
			}
			parent.IngestedAt = s.now().UTC()
			parent.ParentDigest, err = parent.SemanticDigest()
			if err != nil {
				return err
			}
			parent.ID, err = evidence.Digest([]string{d.ID, parent.ConnectionID, parent.ParentID})
			if err != nil {
				return err
			}
			var existing []byte
			err = tx.QueryRowContext(ctx, `SELECT data FROM parents WHERE id=?`, parent.ID).Scan(&existing)
			if err == nil {
				var prior evidence.Observation
				if err := json.Unmarshal(existing, &prior); err != nil {
					return err
				}
				if prior.ParentDigest != parent.ParentDigest {
					return ErrConflict
				}
				result.Duplicates++
				continue
			}
			if err != sql.ErrNoRows {
				return err
			}
			b, err := encode(parent)
			if err != nil {
				return err
			}
			if uint64(len(b)) > s.limits.MaxParentBytes || childCount(parent) > s.limits.MaxParentObjects ||
				d.Records >= 25000 || d.Bytes+uint64(len(b)) > 32<<20 {
				result.Rejected++
				c.RejectedParents++
				result.Reasons[evidence.WithheldBudget]++
				c.Withheld[evidence.WithheldBudget]++
				d.RecordLoss(evidence.CollectionLoss{Code: "budget_exceeded", ConnectionID: parent.ConnectionID})
				continue
			}
			var fitErr error
			if !batchHeadroom {
				fitErr = s.fit(ctx, tx, d.ID, uint64(len(b))+2048, 1, 0)
			}
			if err := fitErr; err != nil {
				if err != ErrBudget {
					return err
				}
				result.Rejected++
				c.RejectedParents++
				result.Reasons[evidence.WithheldBudget]++
				c.Withheld[evidence.WithheldBudget]++
				d.RecordLoss(evidence.CollectionLoss{Code: "budget_exceeded", ConnectionID: parent.ConnectionID})
				continue
			}
			if _, err := tx.ExecContext(ctx, `INSERT INTO parents(id,dataset,expires,data) VALUES(?,?,?,?)`, parent.ID, d.ID, parent.IngestedAt.Add(evidence.Retention).UnixNano(), b); err != nil {
				return err
			}
			d.Records++
			d.Bytes += uint64(len(b))
			result.Accepted++
		}
		// fit may have updated eviction counters; do not overwrite those.
		current, err := counters(ctx, tx)
		if err != nil {
			return err
		}
		current.RejectedParents = c.RejectedParents
		current.LostBatches = c.LostBatches
		current.Withheld = c.Withheld
		if err := saveCounters(ctx, tx, current); err != nil {
			return err
		}
		if req.Seal {
			return s.seal(ctx, tx, d)
		}
		return saveDataset(ctx, tx, d)
	})
	if err != nil {
		return evidence.IngestResult{}, fmt.Errorf("ingest: %w", err)
	}
	return result, nil
}

func childCount(o evidence.Observation) uint32 {
	count := uint64(o.ObjectCount)
	if o.DNP3 != nil {
		var children uint64
		for _, h := range o.DNP3.Objects {
			points := max(uint64(1), uint64(len(h.Spans)))
			if h.Count != nil {
				points = max(points, uint64(*h.Count))
			}
			children += points
		}
		count = max(count, children)
	}
	if o.IEC104 != nil {
		count = max(count, uint64(len(o.IEC104.Objects)))
	}
	if o.Modbus != nil {
		count = max(count, uint64(len(o.Modbus.Spans)), uint64(len(o.Modbus.Values)))
	}
	if count > 4096 {
		return 4097
	}
	return uint32(count)
}

// CountWithheld is idempotent per parent, generator version and reason.
func (s *Store) CountWithheld(ctx context.Context, parent, version string, reason evidence.WithheldReason) error {
	return s.write(ctx, func(tx *sql.Tx) error {
		res, err := tx.ExecContext(ctx, `INSERT OR IGNORE INTO withheld VALUES(?,?,?)`, parent, version, reason)
		if err != nil {
			return err
		}
		n, err := res.RowsAffected()
		if err != nil || n == 0 {
			return err
		}
		c, err := counters(ctx, tx)
		if err != nil {
			return err
		}
		if c.Withheld == nil {
			c.Withheld = map[evidence.WithheldReason]uint64{}
		}
		c.Withheld[reason]++
		b, err := encode(c)
		if err != nil {
			return err
		}
		var dataset string
		var priorBytes uint64
		if err := tx.QueryRowContext(ctx, `SELECT dataset FROM parents WHERE id=?`, parent).Scan(&dataset); err != nil {
			return err
		}
		if err := tx.QueryRowContext(ctx, `SELECT length(data) FROM counters WHERE id=1`).Scan(&priorBytes); err != nil {
			return err
		}
		add := uint64(0)
		if uint64(len(b)) > priorBytes {
			add = uint64(len(b)) - priorBytes
		}
		if err := s.fit(ctx, tx, dataset, add, 0, 0); err != nil {
			return err
		}
		// fit can have advanced cumulative eviction counters.
		current, err := counters(ctx, tx)
		if err != nil {
			return err
		}
		c.EvictedRecords, c.EvictedBytes = current.EvictedRecords, current.EvictedBytes
		return saveCounters(ctx, tx, c)
	})
}

// JSON gauges exclude B-trees, indexes and overflow-page fragmentation. Bound
// actual occupied SQLite pages too, reserving space before attempting a write.
// Whole-dataset eviction frees pages within this same transaction.
func physicalFits(ctx context.Context, tx reader, bytes, records, datasets uint64) (bool, error) {
	var pages, free uint64
	if err := tx.QueryRowContext(ctx, `PRAGMA page_count`).Scan(&pages); err != nil {
		return false, err
	}
	if err := tx.QueryRowContext(ctx, `PRAGMA freelist_count`).Scan(&free); err != nil {
		return false, err
	}
	const databaseBytes = 120 << 20
	const reserve = 8 << 20
	return (pages-free)*4096+2*bytes+16384*(records+datasets) <= databaseBytes-reserve, nil
}
