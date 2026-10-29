// SPDX-License-Identifier: Apache-2.0

package engine

import (
	"net/netip"
	"testing"

	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/tonylturner/containd/pkg/common/metrics"
	"github.com/tonylturner/containd/pkg/dp/flow"
)

// Transport pressure rejects individual arrivals, not Observer.Open. It must
// not inflate the once-per-incarnation observer refusal counter, even when
// both index and queue capacity are exhausted on the same arrival.
func TestObservationTransportLossMetrics(t *testing.T) {
	for _, observer := range []bool{false, true} {
		t.Run(map[bool]string{false: "absent", true: "present"}[observer], func(t *testing.T) {
			e := newObservationEngine(t)
			if !observer {
				live := e.observation
				t.Cleanup(func() { live.observer.Drain(); live.syncMetrics() })
				e.observation = nil
			}
			r := e.transport
			pkt := observationTrace(502, false)[0]
			tuple := packetKey(pkt).Tuple()
			for i := range transportAliasLimit {
				occupied := tuple
				occupied.Source = netip.AddrPortFrom(tuple.Source.Addr(), uint16(i))
				r.indexed[occupied] = &transportAdmission{connection: &flow.Connection{Key: "occupied"}}
			}
			refusals := testutil.ToFloat64(metrics.IdentificationRefusals)
			indexLosses := testutil.ToFloat64(metrics.IdentificationTransportLosses.WithLabelValues("index_capacity"))
			queueLosses := testutil.ToFloat64(metrics.IdentificationTransportLosses.WithLabelValues("queue_capacity"))
			for range 5 {
				r.admit(e, pkt)
				p := <-r.queue
				if p.history != nil {
					t.Fatal("full index admitted a new history")
				}
				r.releaseAdmission(p)
			}
			if len(r.indexed) != transportAliasLimit {
				t.Fatal("metrics added unbounded refusal histories")
			}
			// Both resources are now full. Each packet is counted only as a
			// queue loss, not again as a missing index or refused incarnation.
			r.count.Store(transportQueueLimit)
			for range 5 {
				r.admit(e, pkt)
			}
			r.count.Store(0)
			want := float64(0)
			if observer {
				want = 5
			}
			if delta := testutil.ToFloat64(metrics.IdentificationRefusals) - refusals; delta != 0 {
				t.Fatalf("transport pressure counted %v incarnation refusals", delta)
			}
			if delta := testutil.ToFloat64(metrics.IdentificationTransportLosses.WithLabelValues("index_capacity")) - indexLosses; delta != want {
				t.Fatalf("unindexed packets=%v, want %v", delta, want)
			}
			if delta := testutil.ToFloat64(metrics.IdentificationTransportLosses.WithLabelValues("queue_capacity")) - queueLosses; delta != want {
				t.Fatalf("lost queue packets=%v, want %v", delta, want)
			}
		})
	}
}
