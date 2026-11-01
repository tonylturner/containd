// SPDX-License-Identifier: Apache-2.0
package engineapp

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/tonylturner/containd/pkg/dp/dpi"
	"github.com/tonylturner/containd/pkg/dp/flow"
	"github.com/tonylturner/containd/pkg/dp/learn"
	"github.com/tonylturner/containd/pkg/dp/rules"
	"github.com/tonylturner/containd/pkg/evidence"
)

func TestEvidencePolicyChangeStopsAndExcludesAffectedConnections(t *testing.T) {
	a := newEvidenceTestAPI(t)
	ctx := context.Background()
	watch, err := a.watch.start(ctx, evidence.StartWatchRequest{})
	if err != nil {
		t.Fatal(err)
	}
	state := flow.NewState(flow.Key{SrcIP: net.ParseIP("192.0.2.1"), DstIP: net.ParseIP("192.0.2.2"), DstPort: 502, SrcPort: 40000, Proto: 6}, time.Now())
	events := []dpi.Event{{Proto: "modbus", Kind: "request", Timestamp: time.Now(), Attributes: map[string]any{"function_code": uint8(3), "unit_id": uint8(1), "address": uint16(4), "quantity": uint16(1), "is_write": false}}}
	a.watch.engine.RecordDPIEvents(state, nil, events)
	a.watch.engine.LoadRules(rules.Snapshot{Version: "changed"})
	a.watch.engine.RecordDPIEvents(state, nil, events)
	timeout := time.NewTimer(3 * time.Second)
	defer timeout.Stop()
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case <-timeout.C:
			t.Fatal("policy change did not stop the watch")
		case <-ticker.C:
			stopped, err := a.store.GetWatch(ctx, watch.ID)
			if err != nil {
				t.Fatal(err)
			}
			if stopped.StoppedAt == nil {
				continue
			}
			if stopped.StopReason != "policy_changed" {
				t.Fatal(stopped.StopReason)
			}
			ds, err := a.store.GetDataset(ctx, watch.DatasetID)
			if err != nil || ds.Records != 1 {
				t.Fatalf("complete parent lost: %+v %v", ds, err)
			}
			result, err := a.generator.Generate(ctx, learn.GenerateRequest{DatasetID: ds.ID})
			if err != nil || len(result.Suggestions) != 0 || result.Withheld[evidence.WithheldCollectionLoss] != 1 {
				t.Fatalf("policy collection stop did not exclude affected connection: %+v %v", result, err)
			}
			return
		}
	}
}
