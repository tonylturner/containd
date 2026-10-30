// SPDX-License-Identifier: Apache-2.0
package learn_test

import (
	"context"
	"encoding/binary"
	"net"
	"path/filepath"
	"testing"

	"github.com/tonylturner/containd/pkg/cp/compile"
	"github.com/tonylturner/containd/pkg/cp/config"
	"github.com/tonylturner/containd/pkg/dp/dpi"
	"github.com/tonylturner/containd/pkg/dp/flow"
	"github.com/tonylturner/containd/pkg/dp/ics/eventfields"
	"github.com/tonylturner/containd/pkg/dp/ics/iec104"
	"github.com/tonylturner/containd/pkg/dp/ics/modbus"
	"github.com/tonylturner/containd/pkg/dp/ics/project"
	"github.com/tonylturner/containd/pkg/dp/learn"
	"github.com/tonylturner/containd/pkg/dp/rules"
	"github.com/tonylturner/containd/pkg/evidence"
	"github.com/tonylturner/containd/pkg/evidence/sqlite"
)

func TestCoilCertificateRejectsInvalidWireValues(t *testing.T) {
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
	decode := func(value uint16) []dpi.Event {
		raw := []byte{0, 1, 0, 0, 0, 6, 1, 5, 0, 7, 0, 0}
		binary.BigEndian.PutUint16(raw[10:], value)
		evs, err := modbus.NewDecoder().OnPacket(requestState(), &dpi.ParsedPacket{Payload: raw})
		if err != nil || len(evs) != 1 {
			t.Fatalf("decode: %v", err)
		}
		evs[0].Timestamp = request().Timestamp
		return evs
	}
	state := requestState()
	connection := &flow.Connection{}
	connection.Coverage().Store(true)
	state.Connection.Store(connection)
	var serial uint64
	for _, v := range []uint16{0, 0xff00} {
		p, err := learn.Normalize(ds, state, decode(v), &serial)
		if err != nil {
			t.Fatal(err)
		}
		if _, err = s.Ingest(ctx, evidence.IngestRequest{DatasetID: ds.ID, Parents: p}); err != nil {
			t.Fatal(err)
		}
	}
	if _, err = s.Ingest(ctx, evidence.IngestRequest{DatasetID: ds.ID, Seal: true}); err != nil {
		t.Fatal(err)
	}
	g := learn.Generator{Store: s, Certifier: &learn.CompilerCertifier{Store: s}}
	result, err := g.Generate(ctx, learn.GenerateRequest{DatasetID: ds.ID})
	if err != nil || len(result.Suggestions) != 1 {
		t.Fatalf("closed coil domain: %+v %v", result, err)
	}
	suggestion, err := s.GetSuggestion(ctx, result.Suggestions[0].ID)
	if err != nil {
		t.Fatal(err)
	}
	cfg := config.DefaultConfig()
	cfg.Firewall.Rules = suggestion.Content.Rules
	snap, err := compile.CompileSnapshot(cfg)
	if err != nil {
		t.Fatal(err)
	}
	evaluator := rules.NewEvaluator(&snap)
	for _, v := range []uint16{0, 0xff00, 1, 0x1234, 0xffff} {
		for _, obj := range project.Objects(requestState(), decode(v)[0], iec104.SafeRead) {
			match := evaluator.AnyMatch(rules.EvalContext{SrcIP: net.ParseIP("192.0.2.1"), DstIP: net.ParseIP("192.0.2.2"), Proto: "tcp", Port: "502", ICS: &obj})
			if (match != nil) != (v == 0 || v == 0xff00) {
				t.Errorf("certified ALLOW accepts wire value %#x: %v", v, match != nil)
			}
		}
	}
	found := false
	for _, c := range suggestion.Proof.Counterexamples {
		if c.Mutation == "invalid_coil_value" {
			found = true
		}
	}
	if found {
		t.Fatal("successful proof retained a failed negative")
	}
}

func TestIECDecodedCommandDomainAndQualifier(t *testing.T) {
	for _, typ := range []byte{45, 46, 47} {
		cfg := config.DefaultConfig()
		cfg.Firewall.Rules = []config.Rule{{ID: "command", Action: config.ActionAllow, ICS: config.ICSPredicate{Protocol: "iec104", Mode: "monitor", TypeIDs: []int{int(typ)}, IOA: []config.IOARange{{Start: 7, End: 7}}}}}
		snap, err := compile.CompileSnapshot(cfg)
		if err != nil {
			t.Fatal(err)
		}
		evaluator := rules.NewEvaluator(&snap)
		for q := byte(0); q < 32; q++ {
			for value := byte(0); value < 4; value++ {
				raw := []byte{0x68, 14, 0, 0, 0, 0, typ, 1, 6, 0, 1, 0, 7, 0, 0, value | q<<2}
				result, err := iec104.NewDecoder().ParseStream(requestState(), dpi.StreamView{Bytes: raw, Session: "command", Dir: dpi.ClientToServer})
				if err != nil || len(result.Frames) != 1 {
					t.Fatalf("decode: %+v %v", result, err)
				}
				ev := result.Frames[0].Events[0]
				qualifier, ok := eventfields.Uint8(ev.Attributes, eventfields.KeyQualifier)
				valid := (typ == 45 && value <= 1) || (typ != 45 && (value == 1 || value == 2))
				if valid && (!ok || qualifier != q) {
					t.Fatalf("QU is not the 5-bit field: %v", ev.Attributes)
				}
				objects := project.Objects(requestState(), ev, iec104.SafeRead)
				got := evaluator.AnyMatch(rules.EvalContext{ICS: &objects[0]}) != nil
				want := valid
				if got != want {
					t.Fatalf("type=%d value=%d qualifier=%d accepted=%v", typ, value, q, got)
				}
			}
		}
	}
}
