// SPDX-License-Identifier: Apache-2.0

package pcap

import (
	"bytes"
	"context"
	"net"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/tonylturner/containd/pkg/dp/dpi"
	"github.com/tonylturner/containd/pkg/dp/flow"
	"github.com/tonylturner/containd/pkg/dp/ics/modbus"
	"github.com/tonylturner/containd/pkg/dp/learn"
	"github.com/tonylturner/containd/pkg/evidence"
	"github.com/tonylturner/containd/pkg/evidence/sqlite"
)

func TestImportAndLiveHaveIdenticalRulesAndProof(t *testing.T) {
	ctx := context.Background()
	meta := evidence.Dataset{DecoderVersion: "ics-1", ProfileFingerprint: "profile", SnapshotFingerprint: "snapshot"}
	open := func() *sqlite.Store {
		s, err := sqlite.Open(filepath.Join(t.TempDir(), "evidence.db"), sqlite.Options{CompatibleProof: learn.CompatibleVersions, WatchMetadata: func() (evidence.Dataset, error) { return meta, nil }})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = s.Close() })
		return s
	}
	offline, live := open(), open()
	result, err := Import(ctx, bytes.NewReader(buildPCAP([][]byte{buildModbusEthernetFrame(1)})), offline, meta, AnalysisOptions{}, modbus.NewDecoder())
	if err != nil {
		t.Fatal(err)
	}
	parents, err := offline.ListObservations(ctx, result.Dataset.ID, evidence.PageRequest{})
	if err != nil || len(parents.Items) != 1 {
		t.Fatalf("import lost parent: %+v %v", parents, err)
	}
	if parents.Items[0].Evidence[0].PacketLast == nil {
		t.Fatal("capture reference lost")
	}
	watch, err := live.StartWatch(ctx, evidence.StartWatchRequest{})
	if err != nil {
		t.Fatal(err)
	}
	ds, err := live.GetDataset(ctx, watch.DatasetID)
	if err != nil {
		t.Fatal(err)
	}
	st := flow.NewState(flow.Key{SrcIP: net.ParseIP("10.0.0.1"), DstIP: net.ParseIP("10.0.0.2"), SrcPort: 49152, DstPort: 502, Proto: 6}, parents.Items[0].CapturedAt)
	ev := dpi.Event{Proto: "modbus", Kind: "request", Timestamp: parents.Items[0].CapturedAt, Attributes: map[string]any{"unit_id": uint8(1), "function_code": uint8(3), "address": uint16(0), "quantity": uint16(10), "is_write": false}}
	var serial uint64
	normalized, err := learn.Normalize(ds, st, []dpi.Event{ev}, &serial)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := live.Ingest(ctx, evidence.IngestRequest{DatasetID: ds.ID, Parents: normalized}); err != nil {
		t.Fatal(err)
	}
	if _, err := live.StopWatch(ctx, watch.ID); err != nil {
		t.Fatal(err)
	}
	generate := func(s *sqlite.Store, id string) learn.Suggestion {
		g := learn.Generator{Store: s, Certifier: &learn.CompilerCertifier{Store: s}, CountWithheld: s.CountWithheld}
		out, err := g.Generate(ctx, learn.GenerateRequest{DatasetID: id})
		if err != nil || len(out.Suggestions) != 1 {
			t.Fatalf("generate: %+v %v", out, err)
		}
		proposal, err := s.GetSuggestion(ctx, out.Suggestions[0].ID)
		if err != nil {
			t.Fatal(err)
		}
		return proposal
	}
	a, b := generate(offline, result.Dataset.ID), generate(live, ds.ID)
	if !reflect.DeepEqual(a.Content, b.Content) || a.Proof.ContentID != b.Proof.ContentID || a.Proof.Positive != b.Proof.Positive || a.Proof.Negative != b.Proof.Negative {
		t.Fatalf("source changed rules/proof:\n%+v\n%+v", a, b)
	}
}

func TestImportDisplayCapDoesNotTruncateEvidence(t *testing.T) {
	var frames [][]byte
	for i := range 205 {
		frames = append(frames, buildModbusEthernetFrame(uint32(1+12*i)))
	}
	meta := evidence.Dataset{DecoderVersion: "ics-1", ProfileFingerprint: "profile", SnapshotFingerprint: "snapshot"}
	store, err := sqlite.Open(filepath.Join(t.TempDir(), "evidence.db"), sqlite.Options{CompatibleProof: learn.CompatibleVersions})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	result, err := Import(context.Background(), bytes.NewReader(buildPCAP(frames)), store, meta, AnalysisOptions{}, modbus.NewDecoder())
	if err != nil {
		t.Fatal(err)
	}
	if !result.Stats.DisplayTruncated || result.Stats.Truncated || len(result.Stats.Events) != 200 || result.Dataset.Records != 205 || len(result.Dataset.Gaps) > 0 {
		t.Fatalf("display cap affected evidence: %+v", result.Dataset)
	}
}
