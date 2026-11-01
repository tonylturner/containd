// SPDX-License-Identifier: Apache-2.0
package sqlite

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"github.com/tonylturner/containd/pkg/evidence"
)

func TestParentBatchAdmission(t *testing.T) {
	for _, limit := range []uint64{1, 128} {
		t.Run(fmt.Sprint(limit), func(t *testing.T) {
			s, _, _ := newStore(t, evidence.Budgets{MaxRecords: limit})
			d := create(t, s, "batch")
			first := parent(d, "first")
			got, err := s.Ingest(context.Background(), evidence.IngestRequest{DatasetID: d.ID, Parents: []evidence.Observation{first, first, parent(d, "second")}})
			wantAccepted, wantRejected := uint64(2), uint64(0)
			if limit == 1 {
				wantAccepted, wantRejected = 1, 1
			}
			if err != nil || got.Accepted != wantAccepted || got.Rejected != wantRejected || got.Duplicates != 1 {
				t.Fatalf("batch: %+v %v", got, err)
			}
			again, err := s.Ingest(context.Background(), evidence.IngestRequest{DatasetID: d.ID, Parents: []evidence.Observation{first}})
			if err != nil || again.Duplicates != 1 || again.Accepted != 0 {
				t.Fatalf("persisted duplicate: %+v %v", again, err)
			}
			ds, err := read[evidence.Dataset](context.Background(), s.db, `SELECT data FROM datasets WHERE id=?`, d.ID)
			if err != nil || ds.Records != wantAccepted {
				t.Fatalf("records: %+v %v", ds, err)
			}
			assertGauges(t, s)
		})
	}
}

func TestParentBatchConflictRollsBack(t *testing.T) {
	s, _, _ := newStore(t, evidence.Budgets{})
	d := create(t, s, "conflict")
	first := parent(d, "same")
	changed := parent(d, "same")
	changed.Modbus.FunctionCode = pointer(uint8(4))
	_, err := s.Ingest(context.Background(), evidence.IngestRequest{DatasetID: d.ID, Parents: []evidence.Observation{first, changed}})
	if !errors.Is(err, ErrConflict) {
		t.Fatalf("conflicting pending identity: %v", err)
	}
	ds, err := read[evidence.Dataset](context.Background(), s.db, `SELECT data FROM datasets WHERE id=?`, d.ID)
	if err != nil || ds.Records != 0 {
		t.Fatalf("partial conflict admission: %+v %v", ds, err)
	}
	assertGauges(t, s)
}

func TestParentBatchStatementFailureRollsBack(t *testing.T) {
	s, _, _ := newStore(t, evidence.Budgets{})
	d := create(t, s, "failure")
	// FAIL leaves preceding rows of a multi-row statement intact. The ingest
	// transaction must roll those rows and the accounting triggers back too.
	_, err := s.db.Exec(`CREATE TRIGGER fail_second BEFORE INSERT ON parents WHEN (SELECT COUNT(*) FROM parents)=1 BEGIN SELECT RAISE(FAIL,'fault'); END`)
	if err != nil {
		t.Fatal(err)
	}
	_, err = s.Ingest(context.Background(), evidence.IngestRequest{DatasetID: d.ID, Parents: []evidence.Observation{parent(d, "one"), parent(d, "two")}})
	if err == nil {
		t.Fatal("statement fault accepted")
	}
	var count int
	if err := s.db.QueryRow(`SELECT COUNT(*) FROM parents`).Scan(&count); err != nil || count != 0 {
		t.Fatalf("partial statement rows: %d %v", count, err)
	}
	ds, err := read[evidence.Dataset](context.Background(), s.db, `SELECT data FROM datasets WHERE id=?`, d.ID)
	if err != nil || ds.Records != 0 {
		t.Fatalf("partial statement admission: %+v %v", ds, err)
	}
	assertGauges(t, s)
}

func TestParentBatchMaximumRows(t *testing.T) {
	s, _, _ := newStore(t, evidence.Budgets{})
	d := create(t, s, "maximum")
	parents := make([]evidence.Observation, 128)
	for i := range parents {
		parents[i] = parent(d, fmt.Sprint(i))
	}
	got, err := s.Ingest(context.Background(), evidence.IngestRequest{DatasetID: d.ID, Parents: parents})
	if err != nil || got.Accepted != 128 {
		t.Fatalf("maximum batch: %+v %v", got, err)
	}
	assertGauges(t, s)
}
