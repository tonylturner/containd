// SPDX-License-Identifier: Apache-2.0
package sqlite

import (
	"context"
	"database/sql"
	"strings"
)

type parentInsert struct {
	id      string
	expires int64
	data    []byte
}

// One bounded statement avoids opening a SQLite statement journal for every
// parent in an already-reserved transaction. Row triggers still account for
// every record, and a statement failure rolls back the entire ingest.
func insertParents(ctx context.Context, tx *sql.Tx, dataset string, parents []parentInsert) error {
	if len(parents) == 0 {
		return nil
	}
	values := strings.TrimSuffix(strings.Repeat("(?,?,?,?),", len(parents)), ",")
	args := make([]any, 0, 4*len(parents))
	for _, parent := range parents {
		args = append(args, parent.id, dataset, parent.expires, parent.data)
	}
	_, err := tx.ExecContext(ctx, `INSERT INTO parents(id,dataset,expires,data) VALUES `+values, args...)
	return err
}
