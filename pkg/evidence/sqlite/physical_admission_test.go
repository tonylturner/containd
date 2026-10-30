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
				p.Service.Protocol = "iec104"
				p.Service.ServerPort = 2404
				p.ObjectCount = 512
				p.IEC104 = &evidence.IEC104{APCIType: "I", TypeID: pointer(uint8(45)), CA: pointer(uint16(1)), COT: pointer(uint8(6)), Originator: pointer(uint8(0)), Negative: pointer(false), Test: pointer(false)}
				for j := range 512 {
					p.IEC104.Objects = append(p.IEC104.Objects, evidence.IEC104Object{Index: uint32(j), IOA: pointer(uint32(j)), Select: pointer(false), Qualifier: pointer(uint8(j % 32)), ValueDigest: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"})
				}
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
