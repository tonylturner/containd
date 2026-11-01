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
	"testing"
	"time"

	engineapp "github.com/tonylturner/containd/pkg/app/engine"
	"github.com/tonylturner/containd/pkg/dp/engine"
	"github.com/tonylturner/containd/pkg/dp/learn"
	"github.com/tonylturner/containd/pkg/evidence"
	"github.com/tonylturner/containd/pkg/evidence/sqlite"
)

func TestLiveTransportLossCannotCertifyEarlierParent(t *testing.T) {
	for _, mode := range []string{"clean control", "overflow", "IP truncation"} {
		t.Run(mode, func(t *testing.T) {
			loss := mode != "clean control"
			ctx := context.Background()
			e, exercise := engine.NewLearnerOverflowEngine(t)
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
			s, err := sqlite.Open(filepath.Join(t.TempDir(), "evidence.db"), sqlite.Options{CompatibleProof: learn.CompatibleVersions, WatchMetadata: func() (evidence.Dataset, error) {
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
			var watch evidence.Watch
			if err := json.Unmarshal(request("/internal/learn/watches"), &watch); err != nil {
				t.Fatal(err)
			}
			exercise(mode == "overflow")
			if mode == "IP truncation" {
				e.HandlePacket(capture.Packet{Timestamp: time.Now(), SrcIP: net.ParseIP("10.10.0.5"), DstIP: net.ParseIP("10.20.0.4"), SrcPort: 41000, DstPort: 502, Proto: 6, TCP: capture.TCPMeta{Valid: true}, Invalid: capture.InvalidTruncated})
			}
			request("/internal/learn/watches/" + watch.ID + "/stop")
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
			if loss && (len(ds.Losses) != 1 || ds.Losses[0].ConnectionID != p.ConnectionID) {
				t.Fatalf("wrong incarnation: %+v parent=%+v", ds, p)
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
