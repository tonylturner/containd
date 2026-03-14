// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

package engine

import (
	"net"
	"testing"
	"time"

	"github.com/tonylturner/containd/pkg/dp/capture"
	"github.com/tonylturner/containd/pkg/dp/rules"
)

func BenchmarkHandlePacketModbusRequest(b *testing.B) {
	e, err := New(Config{
		Capture:    capture.Config{},
		DPIEnabled: true,
		InspectAll: true,
	})
	if err != nil {
		b.Fatalf("new engine: %v", err)
	}
	e.LoadRules(rules.Snapshot{
		IDS: rules.IDSConfig{
			Enabled: true,
			Rules: []rules.IDSRule{{
				ID:    "bench-modbus-write",
				Proto: "modbus",
				When: rules.IDSCondition{
					Field: "attr.is_write",
					Op:    "equals",
					Value: false,
				},
				Severity: "low",
			}},
		},
	})

	pkt := capture.Packet{
		Timestamp: time.Unix(1_700_000_000, 0),
		Interface: "bench0",
		SrcIP:     net.ParseIP("10.0.0.10"),
		DstIP:     net.ParseIP("10.0.0.20"),
		SrcPort:   12345,
		DstPort:   502,
		Proto:     6,
		Transport: "tcp",
		Payload:   []byte{0x00, 0x01, 0x00, 0x00, 0x00, 0x06, 0x01, 0x03, 0x00, 0x00, 0x00, 0x02},
	}

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		e.handlePacket(pkt)
	}
}

func BenchmarkHandlePacketHTTPRequest(b *testing.B) {
	e, err := New(Config{
		Capture:    capture.Config{},
		DPIEnabled: true,
		InspectAll: true,
	})
	if err != nil {
		b.Fatalf("new engine: %v", err)
	}

	pkt := capture.Packet{
		Timestamp: time.Unix(1_700_000_000, 0),
		Interface: "bench0",
		SrcIP:     net.ParseIP("10.1.0.10"),
		DstIP:     net.ParseIP("10.1.0.20"),
		SrcPort:   23456,
		DstPort:   80,
		Proto:     6,
		Transport: "tcp",
		Payload:   []byte("GET /index.html HTTP/1.1\r\nHost: bench.example.com\r\nUser-Agent: containd-bench\r\n\r\n"),
	}

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		e.handlePacket(pkt)
	}
}
