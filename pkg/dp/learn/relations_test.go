// SPDX-License-Identifier: Apache-2.0

package learn_test

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"path/filepath"
	"reflect"
	"slices"
	"testing"

	"github.com/tonylturner/containd/pkg/dp/conntrack"
	"github.com/tonylturner/containd/pkg/dp/dpi"
	"github.com/tonylturner/containd/pkg/dp/flow"
	"github.com/tonylturner/containd/pkg/dp/ics/eventfields"
	"github.com/tonylturner/containd/pkg/dp/learn"
	"github.com/tonylturner/containd/pkg/evidence"
	"github.com/tonylturner/containd/pkg/evidence/sqlite"
)

func ptr[T any](v T) *T { return &v }

func TestExactWireAndVerifiedNATCoordinates(t *testing.T) {
	state := requestState()
	ct := &conntrack.Evidence{
		Original: conntrack.Tuple{Family: 2, Protocol: 6, Source: netip.MustParseAddrPort("192.0.2.1:40000"), Destination: netip.MustParseAddrPort("192.0.2.2:502")},
		Reply:    conntrack.Tuple{Family: 2, Protocol: 6, Source: netip.MustParseAddrPort("198.51.100.2:502"), Destination: netip.MustParseAddrPort("198.51.100.1:40000")},
	}
	state.Connection.Store(&flow.Connection{Status: "resolved", Evidence: ct})
	ds := metadata()
	ds.ID = "wire"
	var serial uint64
	wire, err := learn.Normalize(ds, state, []dpi.Event{request()}, &serial)
	if err != nil {
		t.Fatal(err)
	}
	ds.Source = evidence.SourceLive
	live, err := learn.Normalize(ds, state, []dpi.Event{request()}, &serial)
	if err != nil {
		t.Fatal(err)
	}
	if wire[0].Service.ServerIP != "192.0.2.2" || wire[0].Service.Coordinates != evidence.CoordinatesWire || live[0].Service.ServerIP != "198.51.100.2" || live[0].Service.Coordinates != evidence.CoordinatesLogical {
		t.Fatal("wire import adopted logical NAT authority")
	}
	if wire[0].Authority.Logical != nil || live[0].Authority.Logical == nil {
		t.Fatal("coordinate review authority lost")
	}
}

func TestExactDNPStationDirectionDoesNotInventIPRoles(t *testing.T) {
	ds := metadata()
	ds.ID = "station-roles"
	state := requestState()
	state.Key.DstPort = 20000
	ev := dpi.Event{Proto: "dnp3", Kind: "response", Timestamp: request().Timestamp, Attributes: map[string]any{
		eventfields.KeyDirection: "outstation", "source_address": uint16(2), "destination_address": uint16(1), eventfields.KeyFunctionCode: uint8(0x81),
	}}
	var serial uint64
	parents, err := learn.Normalize(ds, state, []dpi.Event{ev}, &serial)
	if err != nil {
		t.Fatal(err)
	}
	if parents[0].Authority.RoleCertain || *parents[0].DNP3.Master != 1 || *parents[0].DNP3.Outstation != 2 {
		t.Fatal("guessed IP orientation overrode station authority")
	}
	state.Key = state.Key.Reversed()
	parents, err = learn.Normalize(ds, state, []dpi.Event{ev}, &serial)
	if err != nil || !parents[0].Authority.RoleCertain || parents[0].Service.Direction != "response" {
		t.Fatal("consistent station/IP roles lost", err)
	}
}

func TestExactDNPHeaderBundleAndFailedReplayRetention(t *testing.T) {
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
	o := parents[0]
	o.Modbus = nil
	o.Service.Protocol, o.Service.ServerPort = "dnp3", 20000
	o.ObjectCount = 2
	o.DNP3 = &evidence.DNP3{Master: ptr(uint16(1)), Outstation: ptr(uint16(2)), FunctionCode: ptr(uint8(1)), Objects: []evidence.DNP3Object{
		{Index: 0, Group: ptr(uint8(20)), Variation: ptr(uint8(1)), Qualifier: ptr(uint8(0)), Count: ptr(uint32(1)), Spans: []evidence.Span{{First: 4, Last: 4, Role: "target"}}},
		{Index: 1, Group: ptr(uint8(30)), Variation: ptr(uint8(2)), Qualifier: ptr(uint8(0)), Count: ptr(uint32(1)), Spans: []evidence.Span{{First: 7, Last: 7, Role: "target"}}},
	}}
	if _, err := store.Ingest(ctx, evidence.IngestRequest{DatasetID: ds.ID, Parents: []evidence.Observation{o}, Seal: true}); err != nil {
		t.Fatal(err)
	}
	g := learn.Generator{Store: store, Certifier: &learn.CompilerCertifier{Store: store}, CountWithheld: store.CountWithheld}
	result, err := g.Generate(ctx, learn.GenerateRequest{DatasetID: ds.ID})
	if err != nil || len(result.Suggestions) != 1 {
		t.Fatalf("unlike DNP headers failed: %+v %v", result, err)
	}
	proposal, err := store.GetSuggestion(ctx, result.Suggestions[0].ID)
	if err != nil || len(proposal.Content.Rules) != 2 {
		t.Fatal("lost atomic unlike-header bundle", err)
	}
	// Deliberately broaden one relation. The real evaluator must produce and
	// retain a counterexample, not turn a failed draft into a stageable proposal.
	content := proposal.Content
	content.Rules[0].ICS.Addresses = []string{"0-100"}
	draft, err := store.PutDraft(ctx, learn.Suggestion{DatasetID: ds.ID, Content: content})
	if err != nil {
		t.Fatal(err)
	}
	certifier := learn.CompilerCertifier{Store: store}
	proof, err := certifier.Certify(ctx, content, proposal.Proof.ParentRefs)
	if !errors.Is(err, learn.ErrNotCertified) || len(proof.Counterexamples) == 0 {
		t.Fatalf("broadened relation passed: %+v %v", proof, err)
	}
	failed, err := store.SaveReplayFailure(ctx, learn.Selection{ID: draft.ID, Revision: draft.Revision}, proof)
	if err != nil || failed.Status != learn.SuggestionDraft || failed.Proof == nil || len(failed.Proof.Counterexamples) == 0 {
		t.Fatal("failed replay disappeared", err)
	}
	if _, err := store.ResolveForStage(ctx, learn.ApplyRequest{RequestID: "failed", Selections: []learn.Selection{{ID: failed.ID, Revision: failed.Revision}}}); !errors.Is(err, learn.ErrStale) {
		t.Fatalf("failed draft staged: %v", err)
	}
}

func TestExactServiceIsolationAndIPv6(t *testing.T) {
	ds := metadata()
	ds.ID = "services"
	var serial uint64
	first, err := learn.Normalize(ds, requestState(), []dpi.Event{request()}, &serial)
	if err != nil {
		t.Fatal(err)
	}
	a, reasons := learn.GenerateRelation(first[0])
	if len(reasons) > 0 {
		t.Fatal(reasons)
	}
	second := first[0]
	second.Service.Protocol, second.Service.ServerPort = "dnp3", 20000
	second.Modbus = nil
	second.DNP3 = &evidence.DNP3{Master: ptr(uint16(1)), Outstation: ptr(uint16(2)), FunctionCode: ptr(uint8(1)), Objects: []evidence.DNP3Object{{Group: ptr(uint8(20)), Variation: ptr(uint8(1)), Qualifier: ptr(uint8(0)), Count: ptr(uint32(1)), Spans: []evidence.Span{{First: 4, Last: 4, Role: "target"}}}}}
	b, reasons := learn.GenerateRelation(second)
	if len(reasons) > 0 || reflect.DeepEqual(a, b) || a[0].ID == b[0].ID {
		t.Fatal("same endpoints merged distinct services", reasons)
	}
	state := requestState()
	state.Key.SrcIP, state.Key.DstIP = net.ParseIP("2001:db8::1"), net.ParseIP("2001:db8::2")
	v6, err := learn.Normalize(ds, state, []dpi.Event{request()}, &serial)
	if err != nil {
		t.Fatal(err)
	}
	rules, reasons := learn.GenerateRelation(v6[0])
	if len(reasons) > 0 || rules[0].Sources[0] != "2001:db8::1/128" {
		t.Fatal("IPv4 mask applied to IPv6", reasons)
	}
}

func TestExactIECWholeParentAndClosedDomainCertification(t *testing.T) {
	for _, typeID := range []uint8{45, 46, 47, 58, 59, 60} {
		t.Run(fmt.Sprint(typeID), func(t *testing.T) {
			ctx := context.Background()
			s, err := sqlite.Open(filepath.Join(t.TempDir(), "evidence.db"), sqlite.Options{CompatibleProof: learn.CompatibleVersions})
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = s.Close() })
			ds, err := s.CreateDataset(ctx, metadata())
			if err != nil {
				t.Fatal(err)
			}
			var serial uint64
			state := requestState()
			state.Key.DstPort = 2404
			event := func(apdu string, value, qualifier uint8) dpi.Event {
				return dpi.Event{Proto: "iec104", Kind: "request", Timestamp: request().Timestamp, Attributes: map[string]any{
					eventfields.KeyAPDUID: apdu, eventfields.KeyAPCIType: "I", eventfields.KeyDirection: "request", eventfields.KeyTypeID: typeID, eventfields.KeyCA: uint16(1), eventfields.KeyCause: uint8(6),
					eventfields.KeyOriginator: uint8(0), eventfields.KeyCOTNegative: false, eventfields.KeyCOTTest: false, eventfields.KeyObjectCount: uint32(1), eventfields.KeyObjectIndex: uint32(0),
					eventfields.KeyIOA: uint32(7), eventfields.KeySelect: false, eventfields.KeyQualifier: qualifier, eventfields.KeyValue: value,
				}}
			}
			// Use the decoder's authoritative field names, not JSON/display aliases.
			for value := range uint8(2) {
				for qualifier := range uint8(32) {
					stateValue := value
					if typeID != 45 && typeID != 58 {
						stateValue++
					}
					ev := event(string(rune(1+int(value)*32+int(qualifier))), stateValue, qualifier)
					parents, err := learn.Normalize(ds, state, []dpi.Event{ev}, &serial)
					if err != nil || len(parents) != 1 {
						t.Fatalf("normalize %v", err)
					}
					if _, err := s.Ingest(ctx, evidence.IngestRequest{DatasetID: ds.ID, Parents: parents}); err != nil {
						t.Fatal(err)
					}
				}
			}
			if _, err := s.Ingest(ctx, evidence.IngestRequest{DatasetID: ds.ID, Seal: true}); err != nil {
				t.Fatal(err)
			}
			g := learn.Generator{Store: s, Certifier: &learn.CompilerCertifier{Store: s}, CountWithheld: s.CountWithheld}
			result, err := g.Generate(ctx, learn.GenerateRequest{DatasetID: ds.ID})
			if err != nil || len(result.Suggestions) != 1 {
				t.Fatalf("full closed domain: %+v %v", result, err)
			}
			proposal, err := s.GetSuggestion(ctx, result.Suggestions[0].ID)
			if err != nil || proposal.Proof.Positive.Total != 64 || proposal.Content.Rules[0].ICS.Mode != "monitor" {
				t.Fatal("whole-parent proof lost", err)
			}
			if _, err := s.ResolveForStage(ctx, learn.ApplyRequest{RequestID: "unreviewed", Selections: result.Suggestions}); err != learn.ErrReviewRequired {
				t.Fatalf("IEC review bypass: %v", err)
			}
			ev := event("incomplete", 1, 0)
			ev.Attributes[eventfields.KeyObjectCount] = uint32(2)
			parents, err := learn.Normalize(ds, state, []dpi.Event{ev}, &serial)
			if err != nil {
				t.Fatal(err)
			}
			if _, reasons := learn.GenerateRelation(parents[0]); !slices.Contains(reasons, evidence.WithheldIncomplete) {
				t.Fatal("incomplete parent yielded partial permission", reasons)
			}
		})
	}
}
