// SPDX-License-Identifier: Apache-2.0

package telemetry

import (
	"context"
	"fmt"
	"os"
)

func (s *Store) diskBytes() (int64, error) {
	var size int64
	for _, path := range []string{s.path, s.path + "-wal"} {
		info, err := os.Stat(path)
		if os.IsNotExist(err) {
			continue
		}
		if err != nil {
			return 0, err
		}
		size += info.Size()
	}
	return size, nil
}

func (s *Store) checkpoint(ctx context.Context) error {
	var busy, log, checkpointed int
	if err := s.db.QueryRowContext(ctx, "PRAGMA wal_checkpoint(TRUNCATE)").Scan(&busy, &log, &checkpointed); err != nil {
		return err
	}
	if busy != 0 {
		return fmt.Errorf("telemetry checkpoint busy")
	}
	return nil
}

// maintain reserves physical headroom before every tick, including the worst
// case of a whole-database dirty transaction. Vacuum/checkpoints are also
// bounded by that reservation, not merely checked after exceeding the budget.
func (s *Store) maintain(ctx context.Context) error {
	if err := s.checkpoint(ctx); err != nil {
		return err
	}
	for {
		if _, err := s.db.ExecContext(ctx, "PRAGMA incremental_vacuum"); err != nil {
			return err
		}
		if err := s.checkpoint(ctx); err != nil {
			return err
		}
		size, err := s.diskBytes()
		if err != nil {
			return err
		}
		if size >= s.budget {
			return fmt.Errorf("telemetry disk budget exhausted")
		}
		// Include 1 MiB for WAL headers/frame overhead and growth headroom. Coarse
		// history may be reclaimed before actual bytes hit the high-water mark.
		if size*2+(1<<20) < s.reclaim {
			return nil
		}
		var floor any
		if err = s.db.QueryRowContext(ctx, "SELECT min(t) FROM buckets WHERE resolution=900").Scan(&floor); err != nil {
			return err
		}
		if floor == nil {
			return nil
		}
		tx, err := s.db.BeginTx(ctx, nil)
		if err != nil {
			return err
		}
		_, err = tx.ExecContext(ctx, "DELETE FROM buckets WHERE resolution=900 AND t=?", floor)
		if err == nil {
			_, err = tx.ExecContext(ctx, `INSERT INTO floors VALUES(900,?+900) ON CONFLICT(resolution) DO UPDATE SET t=max(t,excluded.t)`, floor)
		}
		if err != nil {
			_ = tx.Rollback()
			return err
		}
		if err = tx.Commit(); err != nil {
			return err
		}
		if err = s.checkpoint(ctx); err != nil {
			return err
		}
	}
}
