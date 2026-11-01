// SPDX-License-Identifier: Apache-2.0
package engine

import (
	"net/netip"
	"testing"
	"time"

	"github.com/tonylturner/containd/pkg/dp/capture"
	"github.com/tonylturner/containd/pkg/dp/flow"
	"github.com/tonylturner/containd/pkg/evidence"
)

func TestTransportAdmissionRetainsLossBeforeWorker(t *testing.T) {
	for _, mode := range []string{"byte capacity", "packet capacity", "queue capacity", "notice capacity", "unindexed"} {
		t.Run(mode, func(t *testing.T) {
			e, r, _ := newTransportTest(t, &transportCTFake{evidence: natEvidence()})
			pkt := transportWire(natEvidence().Original, time.Now(), []byte{1})
			pkt.TCP = capture.TCPMeta{Valid: true}
			switch mode {
			case "byte capacity":
				r.bytes.Store(transportByteLimit)
			case "queue capacity":
				for range transportQueueLimit {
					r.queue <- transportPacket{}
				}
			case "notice capacity":
				for range transportQueueLimit {
					r.losses <- transportPacket{}
				}
				r.count.Store(transportQueueLimit)
			case "unindexed":
				for i := range transportAliasLimit {
					tuple := natEvidence().Original
					tuple.Source = netip.AddrPortFrom(tuple.Source.Addr(), uint16(i+1000))
					r.indexed[tuple] = &transportAdmission{connection: &flow.Connection{}}
				}
				r.count.Store(transportQueueLimit)
			default:
				r.count.Store(transportQueueLimit)
			}
			var losses []evidence.CollectionLoss
			e.SetLearnLossHook(func(loss evidence.CollectionLoss) { losses = append(losses, loss) })
			r.admit(e, pkt)
			// No worker, no following packet: even fallback/index exhaustion
			// must already have reached the collecting lease before Stop.
			e.SetLearnLossHook(nil)
			if len(losses) != 1 || losses[0].Code != "capture_loss" || !losses[0].Scope.Ports || losses[0].Scope.Source.IP != pkt.SrcIP.String() || losses[0].Scope.Source.Port != pkt.SrcPort {
				t.Fatalf("upstream loss depended on worker consumption: %+v", losses)
			}
			if mode == "unindexed" && r.unindexedLoss == 0 {
				t.Fatal("fixture did not exhaust the loss index")
			}
			if mode == "notice capacity" && !r.lossFallback.Load() {
				t.Fatal("fixture did not enter fallback")
			}
		})
	}
}
