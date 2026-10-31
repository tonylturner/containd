// SPDX-License-Identifier: Apache-2.0
package sqlite

import (
	"context"
	"fmt"
	"os"
	"testing"

	"github.com/tonylturner/containd/pkg/evidence"
)

func TestPhysicalHeadroomEvictsBeforeSQLiteFull(t *testing.T) {
	ctx := context.Background()
	s, _, path := newStore(t, evidence.Budgets{})
	for d := range 7 {
		ds := create(t, s, fmt.Sprint(d))
		for batch := range 32 {
			var parents []evidence.Observation
			for i := range 8 {
				p := parent(ds, fmt.Sprintf("%d-%d", batch, i))
				p.Modbus = nil
				// A bounded indexed DNP3 read expands compact wire indexes into
				// normalized singleton spans, including realistic JSON amplification.
				p.Service.Protocol = "dnp3"
				p.Service.ServerPort = 20000
				p.ObjectCount = 1536
				object := evidence.DNP3Object{Index: 0, Group: pointer(uint8(20)), Variation: pointer(uint8(1)), Qualifier: pointer(uint8(0x28)), Count: pointer(uint32(1536))}
				for j := range 1536 {
					object.Spans = append(object.Spans, evidence.Span{First: uint32(j), Last: uint32(j), Role: "target"})
				}
				p.DNP3 = &evidence.DNP3{Master: pointer(uint16(1)), Outstation: pointer(uint16(2)), FunctionCode: pointer(uint8(1)), Objects: []evidence.DNP3Object{object}}

				parents = append(parents, p)
			}
			if _, err := s.Ingest(ctx, evidence.IngestRequest{DatasetID: ds.ID, Parents: parents}); err != nil {
				t.Fatalf("physical admission reached SQLite failure at dataset=%d batch=%d: %v", d, batch, err)
			}
		}
		if _, err := s.Ingest(ctx, evidence.IngestRequest{DatasetID: ds.ID, Seal: true}); err != nil {
			t.Fatal(err)
		}
	}
	c, err := s.Counters(ctx)
	if err != nil || c.EvictedRecords == 0 {
		t.Fatalf("physical headroom never evicted: %+v %v", c, err)
	}
	var size int64
	for _, suffix := range []string{"", "-wal", "-shm"} {
		if info, err := os.Stat(path + suffix); err == nil {
			size += info.Size()
		}
	}
	if size > maxPhysical {
		t.Fatalf("physical cap exceeded: %d", size)
	}
}
