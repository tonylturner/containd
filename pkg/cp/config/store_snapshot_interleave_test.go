// SPDX-License-Identifier: Apache-2.0
package config

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"modernc.org/sqlite"
)

// Interpose on the real SQLite driver's rows, not the store response: the
// competing commit happens after a SELECT establishes the read transaction's
// snapshot but before ReadSnapshot reads its next component.
type snapshotConnector struct {
	path     string
	afterRow func(string)
}

func (c snapshotConnector) Connect(context.Context) (driver.Conn, error) {
	conn, err := c.Driver().Open(c.path)
	if err != nil {
		return nil, err
	}
	return snapshotConn{Conn: conn, afterRow: c.afterRow}, nil
}
func (snapshotConnector) Driver() driver.Driver { return &sqlite.Driver{} }

type snapshotConn struct {
	driver.Conn
	afterRow func(string)
}

func (c snapshotConn) BeginTx(ctx context.Context, opts driver.TxOptions) (driver.Tx, error) {
	return c.Conn.(driver.ConnBeginTx).BeginTx(ctx, opts)
}
func (c snapshotConn) QueryContext(ctx context.Context, query string, args []driver.NamedValue) (driver.Rows, error) {
	rows, err := c.Conn.(driver.QueryerContext).QueryContext(ctx, query, args)
	if err != nil {
		return nil, err
	}
	return &snapshotRows{Rows: rows, afterRow: func() { c.afterRow(query) }}, nil
}

type snapshotRows struct {
	driver.Rows
	afterRow func()
}

func (r *snapshotRows) Next(dest []driver.Value) error {
	err := r.Rows.Next(dest)
	if err == nil && r.afterRow != nil {
		hook := r.afterRow
		r.afterRow = nil
		hook()
	}
	return err
}

func TestRevisionSnapshotInterleaving(t *testing.T) {
	for _, withBank := range []bool{false, true} {
		for _, boundary := range []string{"config_revision", "configs", "ids_banks"} {
			if !withBank && boundary == "ids_banks" {
				continue
			}
			t.Run(boundary+map[bool]string{true: "/paired-bank", false: "/paired-bank-free"}[withBank], func(t *testing.T) {
				ctx := context.Background()
				path := filepath.Join(t.TempDir(), "config.db")
				first, err := NewSQLiteStore(path)
				if err != nil {
					t.Fatal(err)
				}
				defer first.Close()
				original := DefaultConfig()
				original.Description = "original"
				if err := first.Save(ctx, original); err != nil {
					t.Fatal(err)
				}
				if err := testCommitConfirmed(first, ctx, time.Hour); err != nil {
					t.Fatal(err)
				}
				replaceGCTestBank(t, first, "old-candidate-bank")
				before, err := first.ReadSnapshot(ctx, SnapshotPair, withBank)
				if err != nil {
					t.Fatal(err)
				}
				second, err := NewSQLiteStore(path)
				if err != nil {
					t.Fatal(err)
				}
				defer second.Close()
				fired := false
				interposed := sql.OpenDB(snapshotConnector{path: path, afterRow: func(query string) {
					if fired || !strings.Contains(query, "FROM "+boundary+" ") && !strings.HasSuffix(query, "FROM "+boundary) {
						return
					}
					fired = true
					newer := DefaultConfig()
					newer.Description = "newer"
					newer.IDS.Rules = []IDSRule{}
					if err := second.Save(ctx, newer); err != nil {
						t.Fatal(err)
					}
					if err := testCommit(second, ctx); err != nil {
						t.Fatal(err)
					} // clears pending too
					replaceGCTestBank(t, second, "new-candidate-bank")
				}})
				defer interposed.Close()
				originalDB := first.db
				first.db = interposed
				snapshot, err := first.ReadSnapshot(ctx, SnapshotPair, withBank)
				first.db = originalDB
				if err != nil {
					t.Fatal(err)
				}
				if !fired {
					t.Fatal("interleaving boundary was not exercised")
				}
				if !reflect.DeepEqual(before, snapshot) {
					t.Fatal("torn snapshot across concurrent commits")
				}
				after, err := second.ReadSnapshot(ctx, SnapshotPair, withBank)
				if err != nil {
					t.Fatal(err)
				}
				if after.Revision == before.Revision || after.PendingConfirm != nil {
					t.Fatal("competing transition did not execute")
				}
			})
		}
	}
}
