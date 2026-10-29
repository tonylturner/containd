// SPDX-License-Identifier: Apache-2.0

package engine

import (
	"context"
	"sort"
	"testing"
	"time"
)

// These isolate cache/lookup bookkeeping and bounded copy admission; the fake
// reader has no kernel latency. End-to-end capture latency needs live traffic.
func BenchmarkTransportResolution(b *testing.B) {
	for _, cold := range []bool{false, true} {
		name := "cache-hit"
		if cold {
			name = "cold-fake-GET"
		}
		b.Run(name, func(b *testing.B) {
			f := &transportCTFake{evidence: natEvidence()}
			r, err := newTransportResolver(&transportZoneFake{}, f)
			if err != nil {
				b.Fatal(err)
			}
			ctx := context.Background()
			r.authority.check(ctx)
			pkt := transportWire(natEvidence().Original, time.Now(), nil)
			r.resolve(ctx, pkt, false)
			samples := make([]int64, b.N)
			b.ReportAllocs()
			b.ResetTimer()
			for i := range b.N {
				if cold {
					clear(r.aliases)
				}
				at := time.Now()
				if !r.resolve(ctx, pkt, false).Verified() {
					b.Fatal("unresolved benchmark")
				}
				samples[i] = time.Since(at).Nanoseconds()
			}
			b.StopTimer()
			sort.Slice(samples, func(i, j int) bool { return samples[i] < samples[j] })
			b.ReportMetric(float64(samples[(len(samples)-1)*95/100]), "p95-ns")
			b.ReportMetric(float64(samples[(len(samples)-1)*99/100]), "p99-ns")
			b.ReportMetric(float64(f.calls-1), "GETs")
			b.ReportMetric(float64(len(r.aliases)), "aliases")
		})
	}
}

func BenchmarkTransportCopyAdmission(b *testing.B) {
	r, err := newTransportResolver(&transportZoneFake{}, &transportCTFake{})
	if err != nil {
		b.Fatal(err)
	}
	e, err := New(Config{InspectAll: true, DPIEnabled: true})
	if err != nil {
		b.Fatal(err)
	}
	pkt := transportWire(natEvidence().Original, time.Now(), make([]byte, 512))
	b.ReportAllocs()
	b.ResetTimer()
	for range b.N {
		r.admit(e, pkt)
		p := <-r.queue
		r.bytes.Add(-int64(len(p.packet.Payload)))
		r.count.Add(-1)
	}
	b.StopTimer()
	b.ReportMetric(float64(r.authority.snapshot().Counters["queue_overflow"]), "lost")
}
