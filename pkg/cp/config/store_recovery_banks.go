// SPDX-License-Identifier: Apache-2.0
package config

import (
	"context"
	"database/sql"
)

type savedBank struct {
	id   int64
	data string
}

// Capture immutable bank bytes under the transition's write lock. Handle-local
// GC holds cannot protect against another handle's sweep. AUTOINCREMENT keeps
// these identities reserved even if collected before compensation.
func captureRecoveryBanks(ctx context.Context, tx *sql.Tx) ([]savedBank, error) {
	rows, err := tx.QueryContext(ctx, `SELECT id, data FROM ids_banks WHERE id IN (
		SELECT CASE WHEN json_valid(data) THEN json_extract(data, '$.ids_bank') END FROM configs
	)`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var banks []savedBank
	for rows.Next() {
		var bank savedBank
		if err := rows.Scan(&bank.id, &bank.data); err != nil {
			return nil, err
		}
		banks = append(banks, bank)
	}
	return banks, rows.Err()
}
