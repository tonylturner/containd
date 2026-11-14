// SPDX-License-Identifier: Apache-2.0

package learn_test

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/tonylturner/containd/pkg/cp/config"
	"github.com/tonylturner/containd/pkg/dp/dpi"
	"github.com/tonylturner/containd/pkg/dp/flow"
	"github.com/tonylturner/containd/pkg/dp/ics/dnp3"
	"github.com/tonylturner/containd/pkg/dp/learn"
	"github.com/tonylturner/containd/pkg/evidence"
	"github.com/tonylturner/containd/pkg/evidence/sqlite"
)

func TestDS34ConsumersLearnerClasses(t *testing.T) {
	for _, tc := range []struct {
		name, protocol, class, direction string
		port                             uint16
		attrs                            map[string]any
	}{
		{"IEC spontaneous", "iec104", "autonomous", "response", 2404, map[string]any{
			"apci_type": "I", "type_id": uint8(1), "cause": uint8(3), "ca": uint16(2), "ioa": uint32(7),
			"originator": uint8(0), "cot_negative": false, "cot_test": false, "object_count": uint32(1), "object_index": uint32(0)}},
		{"DNP unsolicited", "dnp3", "autonomous", "response", 20000, map[string]any{
			"function_code": uint8(130), "application_uns": true, "objects": []dnp3.ObjectHeader{{Group: 1, Variation: 1, HasVariation: true, Qualifier: 0, HasQualifier: true, Count: 1, HasCount: true, Start: ptr(uint32(7)), Stop: ptr(uint32(7))}}}},
		{"IEC session", "iec104", "session", "request", 2404, map[string]any{"apci_type": "U"}},
		{"DNP Confirm", "dnp3", "session", "request", 20000, map[string]any{"function_code": uint8(0)}},
		{"DNP link", "dnp3", "session", "response", 20000, map[string]any{}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			store, err := sqlite.Open(filepath.Join(t.TempDir(), "evidence.db"), sqlite.Options{CompatibleProof: learn.CompatibleVersions})
			if err != nil {
				t.Fatal(err)
			}
			defer store.Close()
			ds, err := store.CreateDataset(ctx, metadata())
			if err != nil {
				t.Fatal(err)
			}
			state := requestState()
			state.Key.DstPort = tc.port
			if tc.direction == "response" {
				state.Key = state.Key.Reversed()
			}
			tc.attrs["direction"] = tc.direction
			tc.attrs["apdu_id"] = "session/0"
			kind := tc.direction
			if tc.protocol == "dnp3" {
				tc.attrs["direction"] = "master"
				tc.attrs["source_address"], tc.attrs["destination_address"] = uint16(1), uint16(2)
				if tc.direction == "response" {
					tc.attrs["direction"] = "outstation"
					tc.attrs["source_address"], tc.attrs["destination_address"] = uint16(2), uint16(1)
					if tc.class == "session" {
						kind = "session"
					}
				}
			}
			var serial uint64
			parents, err := learn.Normalize(ds, state, []dpi.Event{{Proto: tc.protocol, Kind: kind, Timestamp: time.Unix(100, 0), Attributes: tc.attrs}}, &serial)
			if err != nil || len(parents) != 1 || parents[0].MessageClass != tc.class {
				t.Fatalf("classification: %+v %v", parents, err)
			}
			if _, err := store.Ingest(ctx, evidence.IngestRequest{DatasetID: ds.ID, Parents: parents, Seal: true}); err != nil {
				t.Fatal(err)
			}
			g := learn.Generator{Store: store, Certifier: &learn.CompilerCertifier{Store: store}}
			got, err := g.Generate(ctx, learn.GenerateRequest{DatasetID: ds.ID})
			if err != nil || len(got.Suggestions) != 1 {
				t.Fatalf("no certified class relation: %+v %v parents=%+v", got, err, parents)
			}
			suggestion, err := store.GetSuggestion(ctx, got.Suggestions[0].ID)
			if err != nil {
				t.Fatal(err)
			}
			for _, rule := range suggestion.Content.Rules {
				if rule.ICS.MessageClass != tc.class || rule.ICS.Direction != tc.direction || rule.ICS.Mode != "monitor" {
					t.Fatalf("class lost: %+v", rule)
				}
				if tc.class == "autonomous" && tc.protocol == "iec104" && (len(rule.ICS.TypeIDs) == 0 || len(rule.ICS.COT) == 0 || len(rule.ICS.CA) == 0 || len(rule.ICS.IOA) == 0) {
					t.Fatalf("blanket autonomous allowance: %+v", rule)
				}
				if tc.class == "autonomous" && tc.protocol == "dnp3" && (len(rule.ICS.FunctionCode) != 1 || rule.ICS.FunctionCode[0] != 130 || len(rule.ICS.Groups) == 0 || len(rule.ICS.Addresses) == 0) {
					t.Fatalf("blanket autonomous allowance: %+v", rule)
				}
			}
		})
	}
}

func TestDS34ConsumersUnknownSolicitedEvidence(t *testing.T) {
	ds := metadata()
	ds.ID = "replies"
	state := requestState()
	state.Key = state.Key.Reversed()
	state.Key.Dir = flow.DirReverse
	ev := request()
	ev.Kind = "response"
	ev.Attributes["message_class"] = "autonomous" // decoder attributes are not class authority
	ev.Attributes["pairing_outcome"] = "paired"   // offline input cannot certify pairing
	ev.Attributes["pairing_reason"] = "paired"
	var serial uint64
	parents, err := learn.Normalize(ds, state, []dpi.Event{ev}, &serial)
	if err != nil || len(parents) != 1 {
		t.Fatal(parents, err)
	}
	if parents[0].MessageClass != "solicited" || parents[0].PairingOutcome != "" {
		t.Fatalf("offline attributes became authority: %+v", parents[0])
	}
	if bundle, reasons := learn.GenerateRelation(parents[0]); len(bundle) != 0 || len(reasons) == 0 {
		t.Fatalf("uncertain reply generated allowance: %+v %v", bundle, reasons)
	}
}

func TestDS34ConsumersSolicitedCertificationWithheld(t *testing.T) {
	for _, outcome := range []string{"", "unknown", "unsupported"} {
		t.Run(outcome, func(t *testing.T) {
			ctx := context.Background()
			store, err := sqlite.Open(filepath.Join(t.TempDir(), "evidence.db"), sqlite.Options{CompatibleProof: learn.CompatibleVersions, WatchMetadata: func() (evidence.Dataset, error) { return metadata(), nil }})
			if err != nil {
				t.Fatal(err)
			}
			defer store.Close()
			watch, err := store.StartWatch(ctx, evidence.StartWatchRequest{})
			if err != nil {
				t.Fatal(err)
			}
			ds, err := store.GetDataset(ctx, watch.DatasetID)
			if err != nil {
				t.Fatal(err)
			}
			state := requestState()
			state.Key = state.Key.Reversed()
			connection := &flow.Connection{Key: "solicited-session"}
			connection.Coverage().Store(true)
			state.Connection.Store(connection)
			ev := request()
			ev.Kind, ev.Timestamp = "response", time.Now()
			ev.Attributes["pairing_outcome"], ev.Attributes["pairing_reason"] = outcome, "pairing_"+outcome
			var serial uint64
			parents, err := learn.Normalize(ds, state, []dpi.Event{ev}, &serial)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := store.Ingest(ctx, evidence.IngestRequest{DatasetID: ds.ID, Parents: parents}); err != nil {
				t.Fatal(err)
			}
			if _, err := store.StopWatch(ctx, watch.ID); err != nil {
				t.Fatal(err)
			}
			page, err := store.ListObservations(ctx, ds.ID, evidence.PageRequest{})
			if err != nil || len(page.Items) != 1 {
				t.Fatal(page, err)
			}
			digest, err := evidence.EvidenceDigest(page.Items)
			if err != nil {
				t.Fatal(err)
			}
			// A manually authored monitor predicate can match the response,
			// but that is not evidence of a compatible allowed request.
			content := learn.SuggestionContent{EvidenceDigest: digest,
				Versions: learn.Versions{Schema: learn.SuggestionSchemaVersion, Observation: evidence.SchemaVersion,
					Generator: learn.GeneratorVersion, Evaluator: learn.EvaluatorVersion, Decoder: ds.DecoderVersion,
					Profile: ds.ProfileFingerprint, Snapshot: ds.SnapshotFingerprint},
				Rules: []config.Rule{{ID: "manual", Action: config.ActionAllow, ICS: config.ICSPredicate{
					Protocol: "modbus", Mode: "monitor", Direction: "response"}}}}
			certifier := learn.CompilerCertifier{Store: store}
			proof, err := certifier.Certify(ctx, content, []evidence.EvidenceRef{{DatasetID: ds.ID, ObservationID: page.Items[0].ID}})
			if !errors.Is(err, learn.ErrNotCertified) || proof.Positive.Total != 1 || proof.Positive.Failed != 1 || proof.Positive.Passed != 0 {
				t.Fatalf("predicate match certified pairing: %+v %v", proof, err)
			}
		})
	}
}
