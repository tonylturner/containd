// SPDX-License-Identifier: Apache-2.0
package pcap

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/tonylturner/containd/pkg/dp/dpi"
	"github.com/tonylturner/containd/pkg/dp/flow"
	"github.com/tonylturner/containd/pkg/dp/learn"
	"github.com/tonylturner/containd/pkg/evidence"
)

var ErrInvalidCapture = errors.New("invalid capture")

type ImportResult struct {
	Dataset evidence.Dataset `json:"dataset"`
	Stats   AnalysisResult   `json:"stats"`
}

// Import normalizes into the engine's authority. It never generates permission
// and never invokes active packet replay. A failed import is sealed with gaps.
func Import(ctx context.Context, r io.ReadSeeker, store evidence.Store, metadata evidence.Dataset, opts AnalysisOptions, decoders ...dpi.Decoder) (*ImportResult, error) {
	hash := sha256.New()
	if size, err := io.Copy(hash, io.LimitReader(importReader{ctx, r}, (64<<20)+1)); err != nil {
		return nil, err
	} else if size > 64<<20 {
		return nil, fmt.Errorf("%w: capture exceeds 64 MiB", ErrInvalidCapture)
	}
	if _, err := r.Seek(0, io.SeekStart); err != nil {
		return nil, err
	}
	metadata.Source = evidence.SourcePCAP
	metadata.CaptureSHA256 = "sha256:" + hex.EncodeToString(hash.Sum(nil))
	ds, err := store.CreateDataset(ctx, metadata)
	if err != nil {
		return nil, err
	}
	sealed := ds.State == evidence.DatasetSealed
	var ingestErr error
	var serial uint64
	var pending []evidence.Observation
	pendingBytes := 0
	commit := func() {
		if len(pending) == 0 || ingestErr != nil {
			return
		}
		_, ingestErr = store.Ingest(ctx, evidence.IngestRequest{DatasetID: ds.ID, Parents: pending})
		pending, pendingBytes = nil, 0
	}
	opts.MaxFlows = 4096
	opts.MaxDisplayEvents = 200
	opts.OnEvents = func(events []dpi.Event, packet int) {
		if sealed || ingestErr != nil || len(events) == 0 {
			return
		}
		var batch []dpi.Event
		var key flow.Key
		flush := func() {
			if len(batch) == 0 {
				return
			}
			state := &flow.State{Key: key}
			state.Connection.Store(batch[0].Connection)
			parents, err := learn.Normalize(ds, state, batch, &serial)
			if err != nil {
				ingestErr = err
				return
			}
			for _, p := range parents {
				for i := range p.Evidence {
					last := uint64(packet)
					p.Evidence[i].PacketLast = &last
				}
				encoded, err := json.Marshal(p)
				if err != nil {
					ingestErr = err
					return
				}
				if len(pending) == 128 || pendingBytes+len(encoded)+1 > (1<<20)-4096 {
					commit()
					if ingestErr != nil {
						return
					}
				}
				pending = append(pending, p)
				pendingBytes += len(encoded) + 1
			}
			batch = nil
		}
		for _, ev := range events {
			parsed, ok := flow.ParseKey(ev.FlowID)
			if !ok {
				if ev.Proto == "modbus" || ev.Proto == "iec104" || ev.Proto == "dnp3" || ev.Proto == "cip" {
					ingestErr = fmt.Errorf("decoded event lacks wire coordinates")
					return
				}
				continue
			}
			if len(batch) > 0 && parsed.Hash() != key.Hash() {
				flush()
			}
			key = parsed
			batch = append(batch, ev)
		}
		flush()
	}
	stats, parseErr := AnalyzeWithOptions(importReader{ctx, r}, opts, decoders...)
	commit()
	gaps := []string{}
	if parseErr != nil {
		gaps = append(gaps, "import_failed")
	}
	if ingestErr != nil {
		gaps = append(gaps, "ingest_failed")
	}
	if stats != nil && stats.Truncated {
		gaps = append(gaps, "capture_truncated")
	}
	if !sealed {
		sealCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 30*time.Second)
		defer cancel()
		if _, err := store.Ingest(sealCtx, evidence.IngestRequest{DatasetID: ds.ID, Seal: true, Gaps: gaps}); err != nil {
			return nil, err
		}
	}
	if parseErr != nil {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		return nil, fmt.Errorf("%w: %v", ErrInvalidCapture, parseErr)
	}
	if ingestErr != nil {
		return nil, ingestErr
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	ds, err = store.GetDataset(ctx, ds.ID)
	if err != nil {
		return nil, err
	}
	if stats == nil {
		return nil, fmt.Errorf("missing analysis statistics")
	}
	return &ImportResult{Dataset: ds, Stats: *stats}, nil
}

type importReader struct {
	ctx context.Context
	io.Reader
}

func (r importReader) Read(b []byte) (int, error) {
	if err := r.ctx.Err(); err != nil {
		return 0, err
	}
	return r.Reader.Read(b)
}
