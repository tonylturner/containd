// SPDX-License-Identifier: Apache-2.0

package learn_test

import (
	"context"
	"errors"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/tonylturner/containd/pkg/dp/dpi"
	"github.com/tonylturner/containd/pkg/dp/flow"
	"github.com/tonylturner/containd/pkg/dp/ics/eventfields"
	"github.com/tonylturner/containd/pkg/dp/learn"
	"github.com/tonylturner/containd/pkg/evidence"
	"github.com/tonylturner/containd/pkg/evidence/sqlite"
)

func TestConnectionIdentificationWithholdsEarlierParents(t *testing.T) {
	for _, source := range []evidence.Source{evidence.SourcePCAP, evidence.SourceLive} {
		t.Run(string(source), func(t *testing.T) {
			ctx := context.Background()
			store, err := sqlite.Open(filepath.Join(t.TempDir(), "evidence.db"), sqlite.Options{
				CompatibleProof: learn.CompatibleVersions,
				WatchMetadata:   func() (evidence.Dataset, error) { return metadata(), nil },
			})
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = store.Close() })
			var ds evidence.Dataset
			var watch evidence.Watch
			if source == evidence.SourceLive {
				watch, err = store.StartWatch(ctx, evidence.StartWatchRequest{})
				if err != nil {
					t.Fatal(err)
				}
				ds, err = store.GetDataset(ctx, watch.DatasetID)
			} else {
				ds, err = store.CreateDataset(ctx, metadata())
			}
			if err != nil {
				t.Fatal(err)
			}
			state := requestState()
			connection := &flow.Connection{Key: "connection-a"}
			state.Connection.Store(connection)
			var serial uint64
			ingest := func(events ...dpi.Event) {
				t.Helper()
				parents, err := learn.Normalize(ds, state, events, &serial)
				if err != nil {
					t.Fatal(err)
				}
				result, err := store.Ingest(ctx, evidence.IngestRequest{DatasetID: ds.ID, Parents: parents})
				if err != nil || result.Rejected != 0 {
					t.Fatalf("ingest: %+v %v", result, err)
				}
			}
			// The registry-port decoder emits a complete read before content
			// identification finishes. Identification can arrive in reverse.
			ingest(request())
			state.Key = state.Key.Reversed()
			ingest(dpi.Event{Proto: eventfields.ProtoIdentify, Kind: eventfields.KindIdentification,
				Timestamp: request().Timestamp.Add(1), Attributes: map[string]any{
					eventfields.KeyProtocol: "iec104", eventfields.KeyIdentificationState: "confirmed",
					eventfields.KeyBinding: "observation", eventfields.KeyMismatch: true,
				}})
			if source == evidence.SourceLive {
				_, err = store.StopWatch(ctx, watch.ID)
			} else {
				_, err = store.Ingest(ctx, evidence.IngestRequest{DatasetID: ds.ID, Seal: true})
			}
			if err != nil {
				t.Fatal(err)
			}
			g := learn.Generator{Store: store, Certifier: &learn.CompilerCertifier{Store: store}, CountWithheld: store.CountWithheld}
			result, err := g.Generate(ctx, learn.GenerateRequest{DatasetID: ds.ID})
			if err != nil {
				t.Fatal(err)
			}
			if len(result.Suggestions) != 0 {
				t.Fatalf("content mismatch produced %d actionable suggestions: %+v", len(result.Suggestions), result)
			}
			if result.Withheld[learn.WithheldObservationBinding] != 2 {
				t.Fatalf("connection exclusion not visible: %+v", result)
			}
		})
	}
}

func identification(protocol, state, binding string, mismatch bool) dpi.Event {
	return dpi.Event{Proto: eventfields.ProtoIdentify, Kind: eventfields.KindIdentification,
		Timestamp: request().Timestamp.Add(1), Attributes: map[string]any{
			eventfields.KeyProtocol: protocol, eventfields.KeyIdentificationState: state,
			eventfields.KeyBinding: binding, eventfields.KeyMismatch: mismatch,
		}}
}

func TestObservationBindingAuthority(t *testing.T) {
	for _, tc := range []struct {
		name     string
		event    dpi.Event
		retained bool
		excluded bool
	}{
		{"modbus", identification("modbus", "confirmed", "observation", true), true, true},
		{"dnp3", identification("dnp3", "confirmed", "observation", true), true, true},
		{"iec104", identification("iec104", "confirmed", "observation", true), true, true},
		{"cip", identification("cip", "confirmed", "observation", true), true, true},
		{"mismatch without passive decoder", identification("iec104", "confirmed", "none", true), true, true},
		{"mismatch with legacy binding", identification("modbus", "confirmed", "legacy", true), true, true},
		{"matching passive", identification("modbus", "confirmed", "observation", false), false, false},
		{"matching legacy", identification("modbus", "confirmed", "legacy", false), false, false},
		{"candidate", identification("iec104", "candidate", "none", true), false, false},
		{"incomplete", identification("iec104", "identification_incomplete", "none", true), false, false},
		{"unmarked parent", request(), true, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ds := metadata()
			ds.ID = "adapter"
			var serial uint64
			parents, err := learn.Normalize(ds, requestState(), []dpi.Event{tc.event}, &serial)
			if err != nil {
				t.Fatal(err)
			}
			if (len(parents) == 1) != tc.retained {
				t.Fatalf("retained parents: %+v", parents)
			}
			if !tc.retained {
				return
			}
			o := parents[0]
			if err := o.ValidateEnvelope(); err != nil {
				t.Fatal(err)
			}
			rules, reasons := learn.GenerateRelation(o)
			if slices.Contains(reasons, learn.WithheldObservationBinding) != tc.excluded {
				t.Fatalf("rules=%+v reasons=%+v", rules, reasons)
			}
			if tc.excluded && (o.Authority.RoleCertain || len(rules) != 0 || o.Quality.Decoded) {
				t.Fatalf("identification acquired decode/role authority: %+v", o)
			}
		})
	}
	for _, attributes := range []map[string]any{
		{eventfields.KeyObservationOnly: true},
		{eventfields.KeyBindingSource: "observation"},
	} {
		ev := request()
		for k, v := range attributes {
			ev.Attributes[k] = v
		}
		ds := metadata()
		ds.ID = "passive"
		var serial uint64
		state := requestState()
		state.Key.DstPort = 1502
		parents, err := learn.Normalize(ds, state, []dpi.Event{ev}, &serial)
		if err != nil || len(parents) != 1 {
			t.Fatalf("passive parent: %+v %v", parents, err)
		}
		if !parents[0].Quality.Decoded || parents[0].Modbus == nil {
			t.Fatal("passive decoded evidence discarded")
		}
		rules, reasons := learn.GenerateRelation(parents[0])
		if len(rules) != 0 || !slices.Equal(reasons, []evidence.WithheldReason{learn.WithheldObservationBinding}) {
			t.Fatalf("passive parent yielded rules: %+v %v", rules, reasons)
		}
	}
}

func TestConnectionExclusionAcrossPagesAndIncarnations(t *testing.T) {
	for _, passiveOnly := range []bool{false, true} {
		name := "identification"
		if passiveOnly {
			name = "passive-parent"
		}
		t.Run(name, func(t *testing.T) {
			ctx := context.Background()
			path := filepath.Join(t.TempDir(), "evidence.db")
			options := sqlite.Options{CompatibleProof: learn.CompatibleVersions}
			store, err := sqlite.Open(path, options)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = store.Close() })
			ds, err := store.CreateDataset(ctx, metadata())
			if err != nil {
				t.Fatal(err)
			}
			state := requestState()
			state.Connection.Store(&flow.Connection{Key: "excluded-incarnation"})
			var serial uint64
			ingest := func(ev dpi.Event) {
				t.Helper()
				parents, err := learn.Normalize(ds, state, []dpi.Event{ev}, &serial)
				if err != nil {
					t.Fatal(err)
				}
				result, err := store.Ingest(ctx, evidence.IngestRequest{DatasetID: ds.ID, Parents: parents})
				if err != nil || result.Accepted != 1 {
					t.Fatalf("ingest: %+v %v", result, err)
				}
			}
			// More than one page of otherwise usable, identical relations.
			for range 201 {
				ingest(request())
			}
			if passiveOnly {
				ev := request()
				ev.Attributes[eventfields.KeyObservationOnly] = true
				state.Key.DstPort = 1502
				ingest(ev)
				state.Key.DstPort = 502
			} else {
				ingest(identification("iec104", "confirmed", "observation", true))
			}
			// Later legacy events on the excluded connection are also unsafe.
			ingest(request())
			// Reusing exactly the same wire tuple with a new incarnation is
			// independent; its parent is the sole permissible proof reference.
			state.Connection.Store(&flow.Connection{Key: "clean-incarnation"})
			ingest(request())
			if _, err := store.Ingest(ctx, evidence.IngestRequest{DatasetID: ds.ID, Seal: true}); err != nil {
				t.Fatal(err)
			}
			// The exclusion must survive a process/store restart.
			if err := store.Close(); err != nil {
				t.Fatal(err)
			}
			store, err = sqlite.Open(path, options)
			if err != nil {
				t.Fatal(err)
			}
			g := learn.Generator{Store: store, Certifier: &learn.CompilerCertifier{Store: store}, CountWithheld: store.CountWithheld}
			for range 2 {
				result, err := g.Generate(ctx, learn.GenerateRequest{DatasetID: ds.ID})
				if err != nil || len(result.Suggestions) != 1 || result.Withheld[learn.WithheldObservationBinding] != 203 {
					t.Fatalf("connection isolation: %+v %v", result, err)
				}
				suggestion, err := store.GetSuggestion(ctx, result.Suggestions[0].ID)
				if err != nil {
					t.Fatal(err)
				}
				if suggestion.Proof == nil || len(suggestion.Proof.ParentRefs) != 1 {
					t.Fatalf("excluded connection entered proof: %+v", suggestion.Proof)
				}
				if !slices.ContainsFunc(suggestion.Content.Limits, func(s string) bool {
					return strings.Contains(s, "Observation-bound connections are excluded")
				}) {
					t.Fatalf("missing exclusion limitation: %+v", suggestion.Content.Limits)
				}
				// Certification must not bypass the connection decision by
				// loading only an earlier, locally complete legacy parent.
				page, err := store.ListObservations(ctx, ds.ID, evidence.PageRequest{Limit: 200})
				if err != nil {
					t.Fatal(err)
				}
				var legacy evidence.Observation
				for _, o := range page.Items {
					if o.ConnectionID == "excluded-incarnation" && o.Authority.RoleCertain {
						legacy = o
						break
					}
				}
				if legacy.ID == "" {
					t.Fatal("fixture lacks an excluded legacy parent")
				}
				content := suggestion.Content
				content.EvidenceDigest, err = evidence.EvidenceDigest([]evidence.Observation{legacy})
				if err != nil {
					t.Fatal(err)
				}
				c := learn.CompilerCertifier{Store: store}
				if _, err := c.Certify(ctx, content, []evidence.EvidenceRef{{DatasetID: ds.ID, ObservationID: legacy.ID}}); !errors.Is(err, learn.ErrNotCertified) {
					t.Fatalf("certifier accepted excluded connection: %v", err)
				}
			}
			counters, err := store.Counters(ctx)
			if err != nil || counters.Withheld[learn.WithheldObservationBinding] != 203 {
				t.Fatalf("withheld counting is not idempotent: %+v %v", counters, err)
			}
		})
	}
}

func TestObservationBindingSurvivesParentAssembly(t *testing.T) {
	ds := metadata()
	ds.ID = "assembled"
	state := requestState()
	state.Key.DstPort = 12404
	for _, marked := range []int{0, 1} {
		var events []dpi.Event
		for i := range 2 {
			ev := dpi.Event{Proto: "iec104", Kind: "request", Timestamp: request().Timestamp, Attributes: map[string]any{
				eventfields.KeyAPDUID: "apdu", eventfields.KeyAPCIType: "I",
				eventfields.KeyTypeID: uint8(45), eventfields.KeyCA: uint16(1),
				eventfields.KeyObjectCount: uint32(2), eventfields.KeyObjectIndex: uint32(i),
				eventfields.KeyIOA: uint32(100 + i),
			}}
			if i == marked {
				ev.Attributes[eventfields.KeyBindingSource] = "observation"
			}
			events = append(events, ev)
		}
		var serial uint64
		parents, err := learn.Normalize(ds, state, events, &serial)
		if err != nil || len(parents) != 1 || len(parents[0].IEC104.Objects) != 2 {
			t.Fatalf("assembled parent: %+v %v", parents, err)
		}
		rules, reasons := learn.GenerateRelation(parents[0])
		if len(rules) != 0 || !slices.Equal(reasons, []evidence.WithheldReason{learn.WithheldObservationBinding}) {
			t.Fatalf("assembled parent lost binding: %+v %v", rules, reasons)
		}
	}
}

func TestConnectionExclusionRequiresRetainedBindingAuthority(t *testing.T) {
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
	parents, err := learn.Normalize(ds, requestState(), []dpi.Event{request(), request()}, &serial)
	if err != nil {
		t.Fatal(err)
	}
	// Before binding retention, the same authority described both a clean
	// connection and one whose later identification had been discarded.
	parents[0].Authority.RoleEvidence = "decoder_and_connection"
	rules, reasons := learn.GenerateRelation(parents[0])
	if len(rules) != 0 || !slices.Equal(reasons, []evidence.WithheldReason{evidence.WithheldMissingAuthority}) {
		t.Fatalf("historical authority trusted: %+v %v", rules, reasons)
	}
	if _, err := store.Ingest(ctx, evidence.IngestRequest{DatasetID: ds.ID, Parents: parents, Seal: true}); err != nil {
		t.Fatal(err)
	}
	g := learn.Generator{Store: store, Certifier: &learn.CompilerCertifier{Store: store}}
	result, err := g.Generate(ctx, learn.GenerateRequest{DatasetID: ds.ID})
	if err != nil || len(result.Suggestions) != 0 || result.Withheld[evidence.WithheldMissingAuthority] != 2 {
		t.Fatalf("missing binding authority did not exclude connection: %+v %v", result, err)
	}
	v := learn.Versions{Schema: learn.SuggestionSchemaVersion, Observation: evidence.SchemaVersion, Generator: learn.GeneratorVersion, Evaluator: learn.EvaluatorVersion}
	if !learn.CompatibleVersions(v) {
		t.Fatal("current generator rejected")
	}
	v.Generator += "-different"
	if learn.CompatibleVersions(v) {
		t.Fatal("proof from another generator accepted")
	}
}
