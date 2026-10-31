// SPDX-License-Identifier: Apache-2.0
package pcap

import (
	"bytes"
	"context"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/tonylturner/containd/pkg/dp/ics/modbus"
	"github.com/tonylturner/containd/pkg/dp/learn"
	"github.com/tonylturner/containd/pkg/evidence"
	"github.com/tonylturner/containd/pkg/evidence/sqlite"
)

type batchStore struct {
	evidence.Store
	sizes []int
}

func (s *batchStore) Ingest(ctx context.Context, req evidence.IngestRequest) (evidence.IngestResult, error) {
	if len(req.Parents) > 0 {
		s.sizes = append(s.sizes, len(req.Parents))
	}
	return s.Store.Ingest(ctx, req)
}
func TestImportCommitsBoundedParentBatches(t *testing.T) {
	s, err := sqlite.Open(filepath.Join(t.TempDir(), "evidence.db"), sqlite.Options{CompatibleProof: learn.CompatibleVersions})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })
	spy := &batchStore{Store: s}
	var frames [][]byte
	for i := range 205 {
		frames = append(frames, buildModbusEthernetFrame(uint32(1+12*i)))
	}
	result, err := Import(context.Background(), bytes.NewReader(buildPCAP(frames)), spy, evidence.Dataset{DecoderVersion: "ics-1", ProfileFingerprint: "profile", SnapshotFingerprint: "snapshot"}, AnalysisOptions{}, modbus.NewDecoder())
	if err != nil || result.Dataset.Records != 205 {
		t.Fatal("import lost parents", err)
	}
	if !reflect.DeepEqual(spy.sizes, []int{128, 77}) {
		t.Fatalf("one-parent transactions: %v", spy.sizes)
	}
}
