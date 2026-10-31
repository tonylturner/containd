// SPDX-License-Identifier: Apache-2.0

package engine

import (
	"context"
	"net/netip"
	"sort"
	"testing"
	"time"

	"github.com/tonylturner/containd/pkg/dp/capture"
	"github.com/tonylturner/containd/pkg/dp/flow"
)

// These isolate cache/lookup bookkeeping and bounded admission; the fake
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

// Includes admission, alias resolution, flow tracking and coverage, but not the
// reorder timer or kernel GET latency. Empty ACKs keep decoder state bounded.
func BenchmarkTransportHealthyNAT(b *testing.B) {
	e, err := New(Config{InspectAll: true, DPIEnabled: true})
	if err != nil {
		b.Fatal(err)
	}
	r, err := newTransportResolver(&transportZoneFake{}, &transportCTFake{evidence: natEvidence()})
	if err != nil {
		b.Fatal(err)
	}
	e.transport = r
	ctx := context.Background()
	r.authority.check(ctx)
	pkt := transportWire(natEvidence().Original, time.Now(), nil)
	pkt.TCP = capture.TCPMeta{Valid: true, Flags: capture.TCPFlagSYN, Seq: 100}
	process := func() {
		r.admit(e, pkt)
		p := <-r.queue
		if len(r.decodeLossFallback(e, nil)) != 0 {
			b.Fatal("healthy connection lost decode coverage")
		}
		e.handleTransportPacket(p.packet, r.resolve(ctx, p.packet, false), p.history)
		r.releaseAdmission(p)
	}
	process()
	pkt.TCP = capture.TCPMeta{Valid: true, Flags: capture.TCPFlagACK, Seq: 101}
	b.ReportAllocs()
	b.ResetTimer()
	for range b.N {
		process()
	}
}

func BenchmarkTransportFullAliasMiss(b *testing.B) {
	r, err := newTransportResolver(&transportZoneFake{}, &transportCTFake{evidence: natEvidence()})
	if err != nil {
		b.Fatal(err)
	}
	ctx := context.Background()
	r.authority.check(ctx)
	expires := time.Now().Add(time.Hour)
	for i := range transportAliasLimit {
		tuple := natEvidence().Original
		tuple.Source = netip.AddrPortFrom(tuple.Source.Addr(), uint16(i))
		r.aliases[tuple] = &transportAlias{connection: &flow.Connection{Status: "not_found"}, expires: expires}
	}
	pkt := transportWire(natEvidence().Reply, time.Now(), nil)
	if got := r.resolve(ctx, pkt, false); got.Status != "cache_capacity" {
		b.Fatal(got.Status)
	}
	b.ReportAllocs()
	b.ResetTimer()
	for range b.N {
		if got := r.resolve(ctx, pkt, false); got.Status != "cache_capacity" {
			b.Fatal(got.Status)
		}
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
		r.releaseAdmission(p)
	}
	b.StopTimer()
	b.ReportMetric(float64(r.authority.snapshot().Counters["queue_overflow"]), "lost")
}
