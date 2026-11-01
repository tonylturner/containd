// SPDX-License-Identifier: Apache-2.0
package engine

import (
	"context"
	"testing"
	"time"

	"github.com/tonylturner/containd/pkg/dp/capture"
	"github.com/tonylturner/containd/pkg/dp/dpi"
	"github.com/tonylturner/containd/pkg/dp/flow"
	"github.com/tonylturner/containd/pkg/evidence"
)

func TestLearnCaptureHookProvenance(t *testing.T) {
	for _, hook := range []string{evidence.CaptureNFQueue, evidence.CaptureAFPacket, ""} {
		t.Run("hook="+hook, func(t *testing.T) {
			e, _, _ := newTransportTest(t, &transportCTFake{evidence: natEvidence()})
			if hook != evidence.CaptureAFPacket {
				e.transport = nil
			}
			pkt := transportWire(natEvidence().Original, time.Now(), modbusADU(1, 3, 10, 2))
			if hook == evidence.CaptureNFQueue {
				pkt.Token = capture.NewToken(1, 1)
			}
			var got []string
			e.SetLearnWatchHook(func(state *flow.State, _ []dpi.Event) { got = append(got, state.CaptureHook) })
			e.HandlePacket(pkt)
			e.SetLearnWatchHook(nil)
			if len(got) != 1 || got[0] != hook {
				t.Fatalf("parent provenance: got=%v want=%q", got, hook)
			}
			var losses []evidence.CollectionLoss
			e.SetLearnLossHook(func(loss evidence.CollectionLoss) { losses = append(losses, loss) })
			pkt.Invalid, pkt.CaptureIncomplete = capture.InvalidTCPHeader, true
			e.HandlePacket(pkt)
			e.SetLearnLossHook(nil)
			if len(losses) != 1 || losses[0].CaptureHook != hook {
				t.Fatalf("loss provenance: got=%+v want=%q", losses, hook)
			}
		})
	}
}

func TestLearnPacketLossRetainsIndexedIdentity(t *testing.T) {
	for _, ports := range []bool{false, true} {
		t.Run(map[bool]string{false: "partial ports", true: "full ports"}[ports], func(t *testing.T) {
			e, r, _ := newTransportTest(t, &transportCTFake{evidence: natEvidence()})
			pkt := transportWire(natEvidence().Reply, time.Now(), nil)
			r.authority.check(context.Background())
			connection := r.resolve(context.Background(), pkt, false)
			if connection == nil || connection.Key == "" {
				t.Fatal("fixture failed to resolve a live connection")
			}
			r.indexed[packetKey(pkt).Tuple()] = &transportAdmission{connection: connection}
			pkt.PortsValid, pkt.CaptureIncomplete, pkt.Invalid = ports, true, capture.InvalidTCPHeader
			var losses []evidence.CollectionLoss
			e.SetLearnLossHook(func(loss evidence.CollectionLoss) { losses = append(losses, loss) })
			// Exercise the packet entry point, not just the helper, so replacing
			// its indexed lookup with an identity-free callback fails this test.
			e.HandlePacket(pkt)
			e.SetLearnLossHook(nil)
			wantIdentity := ""
			if ports {
				wantIdentity = connection.Key
			}
			if len(losses) != 1 || losses[0].ConnectionID != wantIdentity || losses[0].Scope.Ports != ports || losses[0].Scope.Transport != "tcp" {
				t.Fatalf("indexed truncation identity/scope: ports=%v losses=%+v want=%q", ports, losses, wantIdentity)
			}
		})
	}
}

func TestLearnLossPlaceholderPreservesScope(t *testing.T) {
	e, _, _ := newTransportTest(t, &transportCTFake{evidence: natEvidence()})
	pkt := transportWire(natEvidence().Original, time.Now(), nil)
	pkt.PortsValid = true
	var losses []evidence.CollectionLoss
	e.SetLearnLossHook(func(loss evidence.CollectionLoss) { losses = append(losses, loss) })
	e.recordLearnCaptureLoss(pkt, &flow.Connection{})
	e.recordLearnCaptureLoss(pkt, &flow.Connection{Key: "known"})
	e.SetLearnLossHook(nil)
	if len(losses) != 2 || losses[0].ConnectionID != "" || losses[0].Scope.Transport != "tcp" || losses[1].ConnectionID != "known" || losses[1].Scope != losses[0].Scope {
		t.Fatal("identity erased conservative scope", losses)
	}
}

func TestLearnMalformedIPLossStaysGlobal(t *testing.T) {
	e, r, _ := newTransportTest(t, &transportCTFake{evidence: natEvidence()})
	pkt := transportWire(natEvidence().Original, time.Now(), nil)
	pkt.PortsValid, pkt.CaptureIncomplete, pkt.Invalid = true, true, capture.InvalidIPHeader
	r.indexed[packetKey(pkt).Tuple()] = &transportAdmission{connection: &flow.Connection{Key: "known"}}
	var losses []evidence.CollectionLoss
	e.SetLearnLossHook(func(loss evidence.CollectionLoss) { losses = append(losses, loss) })
	e.recordLearnPacketLoss(pkt)
	e.SetLearnLossHook(nil)
	if len(losses) != 1 || losses[0].ConnectionID != "" || losses[0].Scope != (evidence.LossScope{}) {
		t.Fatal("untrusted IP header acquired narrowing identity", losses)
	}
}
