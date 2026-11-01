// SPDX-License-Identifier: Apache-2.0
package engineapp

import (
	"context"
	"errors"
	"fmt"
	"net"
	"testing"
	"time"

	"github.com/tonylturner/containd/pkg/dp/capture"
	"github.com/tonylturner/containd/pkg/dp/dpi"
	"github.com/tonylturner/containd/pkg/dp/flow"
	"github.com/tonylturner/containd/pkg/dp/learn"
	"github.com/tonylturner/containd/pkg/evidence"
)

func TestUnverifiedLiveCaptureLossUsefulness(t *testing.T) {
	for _, tc := range []struct {
		name, hook                          string
		same, reverse, partial, unknownLoss bool
		wantLoss                            bool
	}{
		{name: "nfqueue unrelated", hook: evidence.CaptureNFQueue},
		{name: "nfqueue same tuple", hook: evidence.CaptureNFQueue, same: true, wantLoss: true},
		{name: "nfqueue reverse tuple", hook: evidence.CaptureNFQueue, same: true, reverse: true, wantLoss: true},
		{name: "nfqueue same hosts partial ports", hook: evidence.CaptureNFQueue, same: true, partial: true, wantLoss: true},
		{name: "nfqueue unrelated partial ports", hook: evidence.CaptureNFQueue, partial: true},
		{name: "nfqueue unknown loss hook", hook: evidence.CaptureNFQueue, unknownLoss: true, wantLoss: true},
		{name: "afpacket unrelated", hook: evidence.CaptureAFPacket, wantLoss: true},
		{name: "unknown parent hook unrelated", wantLoss: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			a := newEvidenceTestAPI(t)
			ctx := context.Background()
			watch, err := a.watch.start(ctx, evidence.StartWatchRequest{})
			if err != nil {
				t.Fatal(err)
			}
			state := flow.NewState(flow.Key{SrcIP: net.ParseIP("192.0.2.1"), DstIP: net.ParseIP("192.0.2.2"), SrcPort: 40000, DstPort: 2404, Proto: 6}, time.Now())
			state.Connection.Store(&flow.Connection{Key: "iec-unverified"})
			if tc.hook == evidence.CaptureNFQueue {
				// The engine stores this receive-time authority for inline
				// packets, independently of conntrack lookup or configuration.
				state.InlinePolicy.Store(&flow.InlinePolicy{Service: state.Key})
			}
			for i := range 3 {
				events := []dpi.Event{iecLoadEvent(fmt.Sprintf("capture-hook/%d", i))}
				if tc.hook == evidence.CaptureAFPacket {
					// Supply the same collector snapshot as a failed AF_PACKET
					// lookup; TestLearnCaptureHookProvenance pins its engine source.
					state.CaptureHook = tc.hook
					a.watch.offer(state, events)
				} else {
					a.watch.engine.RecordDPIEvents(state, nil, events)
				}
			}
			pkt := capture.Packet{IPVersion: 4, SrcIP: net.ParseIP("203.0.113.9"), DstIP: net.ParseIP("203.0.113.10"), SrcPort: 51000, DstPort: 502, Proto: 6, PortsValid: !tc.partial, CaptureIncomplete: true, Invalid: capture.InvalidTCPHeader}
			if !tc.unknownLoss {
				pkt.Token = capture.NewToken(1, 1)
			}
			if tc.same {
				pkt.SrcIP, pkt.DstIP, pkt.SrcPort, pkt.DstPort = state.Key.SrcIP, state.Key.DstIP, state.Key.SrcPort, state.Key.DstPort
			}
			if tc.reverse {
				pkt.SrcIP, pkt.DstIP, pkt.SrcPort, pkt.DstPort = pkt.DstIP, pkt.SrcIP, pkt.DstPort, pkt.SrcPort
			}
			a.watch.engine.HandlePacket(pkt)
			if _, err := a.watch.stop(ctx, watch.ID); err != nil {
				t.Fatal(err)
			}
			ds, err := a.store.GetDataset(ctx, watch.DatasetID)
			if err != nil || ds.Records != 3 || len(ds.Losses) != 1 {
				t.Fatalf("fixture: %+v %v", ds, err)
			}
			wantLossHook := evidence.CaptureNFQueue
			if tc.unknownLoss {
				wantLossHook = ""
			}
			if ds.Losses[0].CaptureHook != wantLossHook {
				t.Fatalf("lost capture provenance: %+v", ds.Losses)
			}
			page, err := a.store.ListObservations(ctx, ds.ID, evidence.PageRequest{})
			if err != nil || len(page.Items) != 3 {
				t.Fatalf("parents: %+v %v", page, err)
			}
			for _, parent := range page.Items {
				if parent.Authority.CaptureHook != tc.hook || parent.Authority.Correlation != "wire" || ds.LossTouches(parent) != tc.wantLoss {
					t.Fatalf("persisted capture/loss authority: %+v %+v", parent.Authority, ds.Losses)
				}
			}
			result, err := a.generator.Generate(ctx, learn.GenerateRequest{DatasetID: ds.ID})
			want := 1
			if tc.wantLoss {
				want = 0
			}
			if err != nil || len(result.Suggestions) != want || tc.wantLoss && result.Withheld[evidence.WithheldCollectionLoss] != 3 {
				t.Fatalf("usefulness/safety: %+v %v", result, err)
			}
			p := page.Items[0]
			rules, reasons := learn.GenerateRelation(p)
			if len(reasons) != 0 {
				t.Fatal(reasons)
			}
			digest, err := evidence.EvidenceDigest([]evidence.Observation{p})
			if err != nil {
				t.Fatal(err)
			}
			content := learn.SuggestionContent{Versions: learn.Versions{Schema: learn.SuggestionSchemaVersion, Observation: evidence.SchemaVersion, Generator: learn.GeneratorVersion, Evaluator: learn.EvaluatorVersion, Decoder: ds.DecoderVersion, Profile: ds.ProfileFingerprint, Snapshot: ds.SnapshotFingerprint}, EvidenceDigest: digest, Rules: rules}
			certifier := learn.CompilerCertifier{Store: a.store}
			proof, err := certifier.Certify(ctx, content, []evidence.EvidenceRef{{DatasetID: ds.ID, ObservationID: p.ID}})
			if tc.wantLoss {
				if !errors.Is(err, learn.ErrNotCertified) || proof.Positive.Total != 0 {
					t.Fatalf("loss escaped direct admission: %+v %v", proof, err)
				}
			} else if err != nil || proof.Positive.Total != 1 {
				t.Fatalf("unrelated loss erased direct usefulness: %+v %v", proof, err)
			}
		})
	}
}
