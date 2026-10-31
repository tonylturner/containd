// SPDX-License-Identifier: Apache-2.0
package learn_test

import (
	"context"
	"net"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"github.com/tonylturner/containd/pkg/dp/dpi"
	"github.com/tonylturner/containd/pkg/dp/flow"
	"github.com/tonylturner/containd/pkg/dp/learn"
	"github.com/tonylturner/containd/pkg/evidence"
	"github.com/tonylturner/containd/pkg/evidence/sqlite"
)

func metadata() evidence.Dataset {
	return evidence.Dataset{SchemaVersion: evidence.SchemaVersion, Source: evidence.SourcePCAP, CaptureSHA256: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", DecoderVersion: "decoder", ProfileFingerprint: "profile", SnapshotFingerprint: "snapshot"}
}
func requestState() *flow.State {
	return &flow.State{Key: flow.Key{SrcIP: net.ParseIP("192.0.2.1"), DstIP: net.ParseIP("192.0.2.2"), SrcPort: 40000, DstPort: 502, Proto: 6, Dir: flow.DirForward}}
}
func request() dpi.Event {
	return dpi.Event{Proto: "modbus", Kind: "request", Timestamp: time.Unix(100, 0), Attributes: map[string]any{"unit_id": uint8(0), "function_code": uint8(3), "is_write": false, "address": uint16(4), "quantity": uint16(3)}}
}
func TestExactAdaptersAndCompilerProof(t *testing.T) {
	ctx := context.Background()
	store, err := sqlite.Open(filepath.Join(t.TempDir(), "evidence.db"), sqlite.Options{CompatibleProof: learn.CompatibleVersions})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	ds, err := store.CreateDataset(ctx, metadata())
	if err != nil {
		t.Fatal(err)
	}
	var serial uint64
	parents, err := learn.Normalize(ds, requestState(), []dpi.Event{request()}, &serial)
	if err != nil {
		t.Fatal(err)
	}
	live := ds
	live.Source = evidence.SourceLive
	live.ID = "live"
	var other uint64
	liveParents, err := learn.Normalize(live, requestState(), []dpi.Event{request()}, &other)
	if err != nil {
		t.Fatal(err)
	}
	a, _ := evidence.EvidenceDigest(parents)
	b, _ := evidence.EvidenceDigest(liveParents)
	if a != b {
		t.Fatalf("source changed normalized relation: %s %s", a, b)
	}
	r1, w1 := learn.GenerateRelation(parents[0])
	r2, w2 := learn.GenerateRelation(liveParents[0])
	if !reflect.DeepEqual(r1, r2) || len(w1)+len(w2) > 0 {
		t.Fatalf("source changed rules: %+v %+v", w1, w2)
	}
	if _, err := store.Ingest(ctx, evidence.IngestRequest{DatasetID: ds.ID, Parents: parents, Seal: true}); err != nil {
		t.Fatal(err)
	}
	generator := learn.Generator{Store: store, Certifier: &learn.CompilerCertifier{Store: store}, CountWithheld: store.CountWithheld}
	result, err := generator.Generate(ctx, learn.GenerateRequest{DatasetID: ds.ID})
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Suggestions) != 1 {
		t.Fatalf("no certified relation: %+v", result)
	}
	suggestion, err := store.GetSuggestion(ctx, result.Suggestions[0].ID)
	if err != nil {
		t.Fatal(err)
	}
	if suggestion.Proof == nil || suggestion.Proof.Positive.Passed != 1 || suggestion.Proof.Negative.Passed < 10 {
		t.Fatalf("incomplete proof: %+v", suggestion.Proof)
	}
	if _, err := generator.Generate(ctx, learn.GenerateRequest{DatasetID: ds.ID}); err != nil {
		t.Fatal(err)
	}
}
func TestExactNoFallbackForFC23AndSubtype(t *testing.T) {
	ds := metadata()
	ds.ID = "test"
	for _, fc := range []uint8{23, 8, 43} {
		ev := request()
		ev.Attributes["function_code"] = fc
		ev.Attributes["read_address"] = uint16(1)
		ev.Attributes["read_quantity"] = uint16(1)
		ev.Attributes["write_address"] = uint16(1)
		ev.Attributes["write_quantity"] = uint16(1)
		ev.Attributes["byte_count"] = uint8(2)
		var serial uint64
		parents, err := learn.Normalize(ds, requestState(), []dpi.Event{ev}, &serial)
		if err != nil {
			t.Fatal(err)
		}
		rules, reasons := learn.GenerateRelation(parents[0])
		if len(rules) != 0 || len(reasons) == 0 {
			t.Fatalf("FC %d broadened: %+v", fc, rules)
		}
	}
	ev := request()
	ev.Attributes["function_code"] = uint8(7)
	var serial uint64
	parents, err := learn.Normalize(ds, requestState(), []dpi.Event{ev}, &serial)
	if err != nil {
		t.Fatal(err)
	}
	rules, reasons := learn.GenerateRelation(parents[0])
	if len(rules) != 1 || len(reasons) != 0 {
		t.Fatalf("bound no-address FC withheld: %+v", reasons)
	}
}
