// SPDX-License-Identifier: Apache-2.0
package engine

import (
	"testing"
	"time"

	"github.com/tonylturner/containd/pkg/dp/capture"
	"github.com/tonylturner/containd/pkg/dp/flow"
	"github.com/tonylturner/containd/pkg/evidence"
)

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
