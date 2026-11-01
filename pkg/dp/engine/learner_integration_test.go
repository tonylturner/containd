// SPDX-License-Identifier: Apache-2.0
package engine_test

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/tonylturner/containd/pkg/dp/capture"
	"github.com/tonylturner/containd/pkg/dp/dpi"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"sort"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	engineapp "github.com/tonylturner/containd/pkg/app/engine"
	"github.com/tonylturner/containd/pkg/dp/engine"
	"github.com/tonylturner/containd/pkg/dp/learn"
	"github.com/tonylturner/containd/pkg/evidence"
	"github.com/tonylturner/containd/pkg/evidence/sqlite"
)

func TestLiveTransportLossCannotCertifyEarlierParent(t *testing.T) {
	for _, mode := range []string{"clean control", "overflow", "pending overflow", "pre-watch overflow", "deadline overflow", "policy overflow", "IP truncation", "short IP header"} {
		t.Run(mode, func(t *testing.T) {
			loss := mode != "clean control"
			ctx := context.Background()
			e, exercise, drain, emit := engine.NewLearnerOverflowEngine(t)
			// Fingerprints bind the test authority to the actual installed registry.
			inputs := e.InspectionSnapshot()
			var enabled []string
			for _, d := range inputs.Decoders {
				if sd, ok := d.(dpi.StreamDecoder); ok {
					enabled = append(enabled, sd.Protocol())
				} else {
					enabled = append(enabled, fmt.Sprintf("%T", d))
				}
			}
			sort.Strings(enabled)
			profile, err := evidence.Digest(struct {
				Parsing map[string]string
				Enabled []string
			}{inputs.Parsing, enabled})
			if err != nil {
				t.Fatal(err)
			}
			snapshot, err := evidence.Digest(inputs.Rules)
			if err != nil {
				t.Fatal(err)
			}
			var clock atomic.Int64
			clock.Store(time.Now().UnixNano())
			s, err := sqlite.Open(filepath.Join(t.TempDir(), "evidence.db"), sqlite.Options{Now: func() time.Time { return time.Unix(0, clock.Load()) }, CompatibleProof: learn.CompatibleVersions, WatchMetadata: func() (evidence.Dataset, error) {
				return evidence.Dataset{DecoderVersion: "ics-1", ProfileFingerprint: profile, SnapshotFingerprint: snapshot}, nil
			}})
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = s.Close() }()
			api := engineapp.NewEvidenceAPI(ctx, s, e)
			defer api.Close()
			mux := http.NewServeMux()
			api.Register(mux)
			request := func(path string) []byte {
				t.Helper()
				rec := httptest.NewRecorder()
				mux.ServeHTTP(rec, httptest.NewRequest("POST", path, strings.NewReader("{}")))
				if rec.Code != 200 {
					t.Fatalf("%s: %d %s", path, rec.Code, rec.Body)
				}
				return rec.Body.Bytes()
			}
			if mode == "pre-watch overflow" {
				exercise(true)
			}
			var watch evidence.Watch
			if err := json.Unmarshal(request("/internal/learn/watches"), &watch); err != nil {
				t.Fatal(err)
			}
			overflow := strings.Contains(mode, "overflow")
			if mode == "pre-watch overflow" {
				emit()
			} else {
				exercise(overflow)
			}
			if mode == "overflow" {
				drain()
			}
			if mode == "IP truncation" || mode == "short IP header" {
				e.HandlePacket(capture.Packet{Timestamp: time.Now(), SrcIP: net.ParseIP("10.10.0.5"), DstIP: net.ParseIP("10.20.0.4"), SrcPort: 41000, DstPort: 502, Proto: 6, TCP: capture.TCPMeta{Valid: mode == "IP truncation"}, Invalid: capture.InvalidTruncated})
			}
			if mode == "deadline overflow" || mode == "policy overflow" {
				expected := "deadline"
				if mode == "policy overflow" {
					expected = "policy_changed"
					e.SetICSParsing(map[string]string{"modbus": "strict"})
				} else {
					clock.Store(watch.Deadline.Add(time.Second).UnixNano())
				}
				limit := time.Now().Add(5 * time.Second)
				for {
					current, err := s.GetWatch(ctx, watch.ID)
					if err != nil {
						t.Fatal(err)
					}
					if current.StoppedAt != nil {
						if current.StopReason != expected {
							t.Fatal(current)
						}
						break
					}
					if time.Now().After(limit) {
						t.Fatal("deadline did not seal")
					}
					time.Sleep(10 * time.Millisecond)
				}
			} else {
				request("/internal/learn/watches/" + watch.ID + "/stop")
			}
			if overflow && mode != "overflow" {
				drain()
			}
			ds, err := s.GetDataset(ctx, watch.DatasetID)
			if err != nil {
				t.Fatal(err)
			}
			page, err := s.ListObservations(ctx, ds.ID, evidence.PageRequest{})
			if err != nil || len(page.Items) != 1 {
				t.Fatalf("earlier parent: %+v %v", page, err)
			}
			p := page.Items[0]
			g := learn.Generator{Store: s, Certifier: &learn.CompilerCertifier{Store: s}}
			out, err := g.Generate(ctx, learn.GenerateRequest{DatasetID: ds.ID})
			if err != nil {
				t.Fatal(err)
			}
			if (len(out.Suggestions) == 0) != loss {
				t.Fatalf("loss=%v suggestions=%+v dataset=%+v", loss, out, ds)
			}
			if loss && !ds.LossTouches(p.ConnectionID, p.Authority.Wire) {
				t.Fatalf("missing exclusion: %+v parent=%+v", ds, p)
			}
			rules, reasons := learn.GenerateRelation(p)
			if len(reasons) > 0 {
				t.Fatal(reasons)
			}
			digest, err := evidence.EvidenceDigest([]evidence.Observation{p})
			if err != nil {
				t.Fatal(err)
			}
			content := learn.SuggestionContent{Versions: learn.Versions{Schema: learn.SuggestionSchemaVersion, Observation: evidence.SchemaVersion, Generator: learn.GeneratorVersion, Evaluator: learn.EvaluatorVersion, Decoder: ds.DecoderVersion, Profile: ds.ProfileFingerprint, Snapshot: ds.SnapshotFingerprint}, EvidenceDigest: digest, Rules: rules}
			_, err = g.Certifier.Certify(ctx, content, []evidence.EvidenceRef{{DatasetID: ds.ID, ObservationID: p.ID}})
			if (err != nil) != loss {
				t.Fatalf("direct certification loss=%v: %v", loss, err)
			}
		})
	}
}
