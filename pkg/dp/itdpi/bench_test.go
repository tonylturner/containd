// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

package itdpi

import (
	"testing"

	"github.com/tonylturner/containd/pkg/dp/dpi"
)

func BenchmarkDNSDecoderQuery(b *testing.B) {
	dec := NewDNSDecoder()
	state := dnsFlowState(12345, 53, 17)
	pkt := &dpi.ParsedPacket{
		Payload: buildDNSQuery(0x1234, "bench.example.com", 1),
		Proto:   "udp",
		SrcPort: 12345,
		DstPort: 53,
	}

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = dec.OnPacket(state, pkt)
	}
}

func BenchmarkHTTPDecoderRequest(b *testing.B) {
	dec := NewHTTPDecoder()
	state := httpFlowState(12345, 80)
	pkt := &dpi.ParsedPacket{
		Payload: []byte("GET /index.html HTTP/1.1\r\nHost: bench.example.com\r\nUser-Agent: containd-bench\r\n\r\n"),
		Proto:   "tcp",
		SrcPort: 12345,
		DstPort: 80,
	}

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = dec.OnPacket(state, pkt)
	}
}

func BenchmarkTLSDecoderClientHello(b *testing.B) {
	dec := NewTLSDecoder()
	state := tlsFlowState(12345, 443)
	pkt := &dpi.ParsedPacket{
		Payload: buildClientHello("bench.example.com", []string{"h2", "http/1.1"}),
		Proto:   "tcp",
		SrcPort: 12345,
		DstPort: 443,
	}

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = dec.OnPacket(state, pkt)
	}
}
