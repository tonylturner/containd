// SPDX-License-Identifier: Apache-2.0

package engine

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/tonylturner/containd/pkg/dp/capture"
	"github.com/tonylturner/containd/pkg/dp/dpi"
	"github.com/tonylturner/containd/pkg/dp/flow"
	"github.com/tonylturner/containd/pkg/dp/learn"
	"github.com/tonylturner/containd/pkg/dp/rules"
	"github.com/tonylturner/containd/pkg/dp/session"
	"github.com/tonylturner/containd/pkg/evidence"
	"github.com/tonylturner/containd/pkg/evidence/sqlite"
)

func TestLearnerStandardPortIEC104(t *testing.T) {
	for _, inline := range []bool{false, true} {
		t.Run(map[bool]string{false: "afpacket", true: "nfqueue"}[inline], func(t *testing.T) {
			cfg := Config{Capture: capture.Config{Interfaces: []string{"eth0"}}, DPIEnabled: true, ResetInjector: &session.Fake{}}
			snap := rules.Snapshot{Default: rules.ActionAllow}
			if inline {
				cfg.NFQueueGroup = 101
				snap.Firewall = []rules.Entry{{ID: "inspect", ICS: rules.ICSPredicate{Protocol: "iec104", Mode: "monitor"}, Action: rules.ActionAllow}}
			}
			e, err := New(cfg)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() {
				if e.observation != nil {
					e.observation.observer.Drain()
					e.observation.syncMetrics()
				}
			})
			e.LoadRules(snap)
			ctx := context.Background()
			store, err := sqlite.Open(filepath.Join(t.TempDir(), "evidence.db"), sqlite.Options{
				CompatibleProof: learn.CompatibleVersions,
				WatchMetadata: func() (evidence.Dataset, error) {
					return evidence.Dataset{DecoderVersion: "ics-1", ProfileFingerprint: "profile", SnapshotFingerprint: "snapshot"}, nil
				},
			})
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = store.Close() })
			watch, err := store.StartWatch(ctx, evidence.StartWatchRequest{})
			if err != nil {
				t.Fatal(err)
			}
			ds, err := store.GetDataset(ctx, watch.DatasetID)
			if err != nil {
				t.Fatal(err)
			}
			var serial uint64
			e.SetLearnWatchHook(func(st *flow.State, events []dpi.Event) {
				if st == nil {
					return
				}
				parents, err := learn.Normalize(ds, st, events, &serial)
				if err != nil {
					t.Fatal(err)
				}
				if result, err := store.Ingest(ctx, evidence.IngestRequest{DatasetID: ds.ID, Parents: parents}); err != nil || result.Rejected != 0 {
					t.Fatalf("ingest: %+v %v", result, err)
				}
			})
			trace := observationTrace(2404, true)
			trace[4].Payload = apdu(46, 6, 1, 2001, 1)
			for i, pkt := range trace {
				pkt.Timestamp = time.Now().Add(time.Duration(i) * time.Microsecond)
				e.HandlePacket(pkt)
			}
			e.SetLearnWatchHook(nil)
			if _, err := store.StopWatch(ctx, watch.ID); err != nil {
				t.Fatal(err)
			}
			g := learn.Generator{Store: store, Certifier: &learn.CompilerCertifier{Store: store}}
			result, err := g.Generate(ctx, learn.GenerateRequest{DatasetID: ds.ID})
			if err != nil {
				t.Fatal(err)
			}
			for _, selection := range result.Suggestions {
				suggestion, err := store.GetSuggestion(ctx, selection.ID)
				if err != nil {
					t.Fatal(err)
				}
				for _, rule := range suggestion.Content.Rules {
					if len(rule.ICS.TypeIDs) == 1 && rule.ICS.TypeIDs[0] == 46 &&
						len(rule.ICS.CommandStates) == 1 && rule.ICS.CommandStates[0] == 1 &&
						len(rule.ICS.CommandQualifiers) == 1 && rule.ICS.CommandQualifiers[0] == 0 &&
						rule.ICS.SelectExecute == "execute" {
						return
					}
				}
			}
			t.Fatalf("normal Type-46 command did not certify: %+v", result)
		})
	}
}
