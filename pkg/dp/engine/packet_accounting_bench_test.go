// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

package engine

import (
	"net"
	"testing"
	"time"

	"github.com/tonylturner/containd/pkg/dp/capture"
	"github.com/tonylturner/containd/pkg/dp/flow"
)

func BenchmarkRecordPacketStats(b *testing.B) {
	for _, tc := range []struct {
		name, src, dst string
		port           uint16
	}{
		{"IPv4", "10.0.0.1", "10.0.0.2", 502},
		{"IPv6", "2001:db8::1", "2001:db8::2", 502},
		{"SharedPort", "10.0.0.1", "10.0.0.2", 102},
	} {
		b.Run(tc.name, func(b *testing.B) {
			e, err := New(Config{DPIEnabled: true})
			if err != nil {
				b.Fatal(err)
			}
			pkt := capture.Packet{
				SrcIP: net.ParseIP(tc.src), DstIP: net.ParseIP(tc.dst),
				SrcPort: 40000, DstPort: tc.port, Proto: 6, Transport: "tcp",
				Timestamp: time.Now().UTC(), Payload: make([]byte, 64),
			}
			state := flow.NewState(flow.Key{
				SrcIP: pkt.SrcIP, DstIP: pkt.DstIP, SrcPort: pkt.SrcPort, DstPort: pkt.DstPort, Proto: 6,
			}, pkt.Timestamp)
			e.recordPacketStats(pkt, state) // Resolve the flow and allocate counters once.
			b.ReportAllocs()
			b.ResetTimer()
			for b.Loop() {
				e.recordPacketStats(pkt, state)
			}
		})
	}
}
