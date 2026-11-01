// SPDX-License-Identifier: Apache-2.0
package engineapp

import (
	"context"
	"database/sql"
	"fmt"
	"net"
	"path/filepath"
	"testing"
	"time"

	"github.com/tonylturner/containd/pkg/dp/dpi"
	"github.com/tonylturner/containd/pkg/dp/engine"
	"github.com/tonylturner/containd/pkg/dp/flow"
	"github.com/tonylturner/containd/pkg/dp/learn"
	"github.com/tonylturner/containd/pkg/evidence"
	"github.com/tonylturner/containd/pkg/evidence/sqlite"
)

func TestStopRetryCannotForgetLoss(t *testing.T) {
	for _, barrierFailure := range []bool{false, true} {
		t.Run(map[bool]string{false: "loss flush", true: "barrier and storage"}[barrierFailure], func(t *testing.T) {
			check := func(err error) {
				t.Helper()
				if err != nil {
					t.Fatal(err)
				}
			}
			ctx := context.Background()
			e, err := engine.New(engine.Config{})
			check(err)
			path := filepath.Join(t.TempDir(), "evidence.db")
			s, err := sqlite.Open(path, sqlite.Options{CompatibleProof: learn.CompatibleVersions, WatchMetadata: func() (evidence.Dataset, error) { return evidenceMetadata(e) }})
			check(err)
			defer s.Close()
			watch, err := s.StartWatch(ctx, evidence.StartWatchRequest{})
			check(err)
			ds, err := s.GetDataset(ctx, watch.DatasetID)
			check(err)
			// Omit the periodic maintainer to control the final flush boundary.
			w := &evidenceWatch{queue: make(chan evidenceBatch, 64), done: make(chan struct{}), store: s, engine: e}
			lease := &watchLease{dataset: ds, watch: watch, token: e.InspectionToken()}
			w.active.Store(lease)
			st := flow.NewState(flow.Key{SrcIP: net.ParseIP("192.0.2.1"), DstIP: net.ParseIP("192.0.2.2"), SrcPort: 40000, DstPort: 502, Proto: 6}, time.Now())
			st.Connection.Store(&flow.Connection{Key: "affected"})
			ev := dpi.Event{Proto: "modbus", Kind: "request", Timestamp: time.Now(), Attributes: map[string]any{"unit_id": uint8(1), "function_code": uint8(3), "address": uint16(4), "quantity": uint16(3), "is_write": false}}
			var serial uint64
			parents, err := learn.Normalize(ds, st, []dpi.Event{ev}, &serial)
			check(err)
			_, err = s.Ingest(ctx, evidence.IngestRequest{DatasetID: ds.ID, Parents: parents})
			check(err)
			lease.drop(st, []dpi.Event{ev})
			if barrierFailure {
				w.fail(fmt.Errorf("prior ingest failed"))
			}
			db, err := sql.Open("sqlite", path)
			check(err)
			defer db.Close()
			_, err = db.Exec(`CREATE TRIGGER deny_loss BEFORE UPDATE OF data ON datasets WHEN json_array_length(json_extract(NEW.data, '$.losses')) > 0 BEGIN SELECT RAISE(FAIL,'injected loss write failure'); END`)
			check(err)
			worker, cancel := context.WithCancel(ctx)
			go w.run(worker)
			defer func() { cancel(); <-w.done }()
			_, err = w.stop(ctx, watch.ID)
			if err == nil {
				t.Fatal("fault injection failed")
			}
			t.Logf("first stop: %v", err)
			_, err = db.Exec(`DROP TRIGGER deny_loss`)
			check(err)
			_, err = w.stop(ctx, watch.ID)
			check(err)
			ds, err = s.GetDataset(ctx, ds.ID)
			check(err)
			g := learn.Generator{Store: s, Certifier: &learn.CompilerCertifier{Store: s}}
			out, err := g.Generate(ctx, learn.GenerateRequest{DatasetID: ds.ID})
			check(err)
			t.Logf("retry sealed dataset: records=%d gaps=%v losses=%v suggestions=%d", ds.Records, ds.Gaps, ds.Losses, len(out.Suggestions))
			found := false
			for _, loss := range ds.Losses {
				found = found || loss.ConnectionID == "affected"
			}
			if !found || w.stopping != nil {
				t.Fatal("retry did not recover the detached loss lease")
			}
			if len(out.Suggestions) > 0 {
				t.Fatal("failed loss flush was forgotten by stop retry")
			}

		})
	}
}
