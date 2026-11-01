// SPDX-License-Identifier: Apache-2.0
package engineapp

import (
	"context"
	"net/netip"
	"testing"
	"time"

	"github.com/tonylturner/containd/pkg/dp/capture"
	"github.com/tonylturner/containd/pkg/dp/conntrack"
	"github.com/tonylturner/containd/pkg/dp/dpi"
	"github.com/tonylturner/containd/pkg/dp/flow"
	"github.com/tonylturner/containd/pkg/dp/learn"
	"github.com/tonylturner/containd/pkg/evidence"
)

func verifiedLearnState(id, client, server, translated string) *flow.State {
	tuple := func(src, dst string) conntrack.Tuple {
		return conntrack.Tuple{Family: 2, Protocol: 6, Source: netip.MustParseAddrPort(src), Destination: netip.MustParseAddrPort(dst)}
	}
	ct := &conntrack.Evidence{Original: tuple(client, server), Reply: tuple(server, translated)}
	state := flow.NewState(flow.TupleKey(ct.Original, flow.DirForward), time.Now())
	state.Connection.Store(&flow.Connection{Key: id, Status: "resolved", Evidence: ct})
	return state
}
func recordRead(a *EvidenceAPI, state *flow.State) {
	a.watch.engine.RecordDPIEvents(state, nil, readEvents())
}
func readEvents() []dpi.Event {
	return []dpi.Event{{Proto: "modbus", Kind: "request", Timestamp: time.Now(), Attributes: map[string]any{"function_code": uint8(3), "unit_id": uint8(1), "address": uint16(4), "quantity": uint16(1), "is_write": false}}}
}
func truncateReply(a *EvidenceAPI, state *flow.State, ports bool) {
	key := flow.TupleKey(state.Connection.Load().Evidence.Reply, flow.DirReverse)
	pkt := capture.Packet{SrcIP: key.SrcIP, DstIP: key.DstIP, SrcPort: key.SrcPort, DstPort: key.DstPort, Proto: 6, PortsValid: ports, CaptureIncomplete: true, Invalid: capture.InvalidTCPHeader}
	if !ports {
		pkt.SrcPort, pkt.DstPort = 0, 0
	}
	a.watch.engine.HandlePacket(pkt)
}

func TestStopClosesParentsBeforeLossFence(t *testing.T) {
	for _, when := range []string{"before loss detach", "after loss detach"} {
		t.Run(when, func(t *testing.T) {
			a := newEvidenceTestAPI(t)
			ctx := context.Background()
			watch, err := a.watch.start(ctx, evidence.StartWatchRequest{})
			if err != nil {
				t.Fatal(err)
			}
			clean := verifiedLearnState("clean", "192.0.2.1:40000", "192.0.2.2:502", "192.0.2.1:40000")
			late := verifiedLearnState("late", "198.51.100.1:40000", "198.51.100.2:502", "198.51.100.1:40000")
			recordRead(a, clean)
			// Model a resolver that already loaded the semantic callback:
			// clearing the engine's hook alone cannot revoke this copy.
			pendingOffer := a.watch.offer
			// Execute the exact interleaving at the loss setter, without scheduler
			// timing: a loss and then a parent from its connection try to cross Stop.
			called := false
			_, err = a.watch.stopWithLossFence(ctx, watch.ID, func() {
				called = true
				if when == "before loss detach" {
					truncateReply(a, late, true)
				}
				a.watch.engine.SetLearnLossHook(nil)
				if when == "after loss detach" {
					truncateReply(a, late, true)
				}
				pendingOffer(late, readEvents())
			})
			if err != nil || !called {
				t.Fatalf("stop: %v injected=%v", err, called)
			}
			ds, err := a.store.GetDataset(ctx, watch.DatasetID)
			if err != nil || ds.Records != 1 {
				t.Fatalf("parent crossed closed loss boundary: %+v %v", ds, err)
			}
			out, err := a.generator.Generate(ctx, learn.GenerateRequest{DatasetID: ds.ID})
			if err != nil || len(out.Suggestions) != 1 {
				t.Fatalf("clean control lost usefulness: %+v %v", out, err)
			}
		})
	}
}

func TestLiveNATAliasLossUsefulness(t *testing.T) {
	for _, mode := range []string{"clean", "ports", "host pair"} {
		t.Run(mode, func(t *testing.T) {
			a := newEvidenceTestAPI(t)
			ctx := context.Background()
			watch, err := a.watch.start(ctx, evidence.StartWatchRequest{})
			if err != nil {
				t.Fatal(err)
			}
			first := verifiedLearnState("first", "10.10.0.5:41000", "10.20.0.4:502", "10.20.0.2:52000")
			second := verifiedLearnState("second", "10.10.0.5:41001", "10.20.0.4:502", "10.20.0.2:52001")
			recordRead(a, first)
			recordRead(a, second)
			if mode != "clean" {
				truncateReply(a, first, mode == "ports")
			}
			if _, err := a.watch.stop(ctx, watch.ID); err != nil {
				t.Fatal(err)
			}
			out, err := a.generator.Generate(ctx, learn.GenerateRequest{DatasetID: watch.DatasetID})
			want := 1
			if mode == "host pair" {
				want = 0
			}
			if err != nil || len(out.Suggestions) != want {
				t.Fatalf("NAT usefulness: %+v %v", out, err)
			}
			if want > 0 {
				suggestion, err := a.store.GetSuggestion(ctx, out.Suggestions[0].ID)
				positives := uint64(2)
				if mode == "ports" {
					positives = 1
				}
				if err != nil || suggestion.Proof == nil || suggestion.Proof.Positive.Total != positives {
					t.Fatalf("NAT positives: %+v %v", suggestion, err)
				}
			}
		})
	}
}
