// SPDX-License-Identifier: Apache-2.0
package learn_test

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/tonylturner/containd/pkg/dp/dpi"
	"github.com/tonylturner/containd/pkg/dp/flow"
	"github.com/tonylturner/containd/pkg/dp/ics/dnp3"
	"github.com/tonylturner/containd/pkg/dp/ics/modbus"
	"github.com/tonylturner/containd/pkg/dp/learn"
	"github.com/tonylturner/containd/pkg/evidence"
	"github.com/tonylturner/containd/pkg/evidence/sqlite"
)

func TestGenerateWithholdsUnboundWriteValues(t *testing.T) {
	for _, tc := range []struct {
		name   string
		raw    []byte
		reason evidence.WithheldReason
	}{
		{"FC6", []byte{0, 1, 0, 0, 0, 6, 1, 6, 0, 7, 0, 1}, evidence.WithheldModbusValues},
		{"FC16", []byte{0, 1, 0, 0, 0, 9, 1, 16, 0, 7, 0, 1, 2, 0, 1}, evidence.WithheldModbusValues},
		{"g12v1_CROB", nil, evidence.WithheldDNP3Values},
	} {
		t.Run(tc.name, func(t *testing.T) {
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
			state := requestState()
			c := &flow.Connection{}
			c.Coverage().Store(true)
			state.Connection.Store(c)
			var events []dpi.Event
			if tc.raw != nil {
				events, err = modbus.NewDecoder().OnPacket(state, &dpi.ParsedPacket{Payload: tc.raw})
				if err != nil || len(events) != 1 {
					t.Fatal("write decode", err)
				}
				events[0].Timestamp = request().Timestamp
			} else {
				state.Key.DstPort = 20000
				headers := dnp3.ParseObjectHeaders([]byte{12, 1, 0x17, 1, 7, 3, 1, 100, 0, 0, 0, 0, 0, 0, 0, 0}, 0, 5)
				if len(headers) != 1 || headers[0].DataDigest == "" {
					t.Fatal("CROB decoder lost value authority")
				}
				events = []dpi.Event{{Proto: "dnp3", Kind: "request", Timestamp: request().Timestamp, Attributes: map[string]any{"function_code": uint8(5), "is_write": true, "source_address": uint16(1), "destination_address": uint16(2), "direction": "master", "objects": headers}}}
			}
			var serial uint64
			parents, err := learn.Normalize(ds, state, events, &serial)
			if err != nil || len(parents) != 1 {
				t.Fatal("normalize", err)
			}
			if _, err := s.Ingest(ctx, evidence.IngestRequest{DatasetID: ds.ID, Parents: parents, Seal: true}); err != nil {
				t.Fatal(err)
			}
			g := learn.Generator{Store: s, Certifier: &learn.CompilerCertifier{Store: s}}
			result, err := g.Generate(ctx, learn.GenerateRequest{DatasetID: ds.ID})
			if err != nil || len(result.Suggestions) != 0 || result.Withheld[tc.reason] != 1 {
				t.Fatalf("unbound write passed generation: %+v %v", result, err)
			}
		})
	}
}
