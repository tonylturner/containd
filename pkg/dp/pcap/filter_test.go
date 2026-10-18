// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

//go:build linux

package pcap

import (
	"testing"

	"github.com/tonylturner/containd/pkg/cp/config"
)

func TestMatchFilterPort(t *testing.T) {
	tcp := portTestFrame(6, 1024, 2404, 0)
	udp := portTestFrame(17, 53, 40000, 0)

	tests := []struct {
		name   string
		packet []byte
		filter config.PCAPFilter
		want   bool
	}{
		{name: "destination", packet: tcp, filter: config.PCAPFilter{Port: "2404"}, want: true},
		{name: "source", packet: tcp, filter: config.PCAPFilter{Port: "1000-1100"}, want: true},
		{name: "range miss", packet: tcp, filter: config.PCAPFilter{Port: "2405-2410"}},
		{name: "protocol and port", packet: tcp, filter: config.PCAPFilter{Proto: "tcp", Port: "2404"}, want: true},
		{name: "wrong protocol", packet: udp, filter: config.PCAPFilter{Proto: "tcp", Port: "53"}},
		{name: "udp", packet: udp, filter: config.PCAPFilter{Port: "53"}, want: true},
		{name: "icmp cannot match", packet: portTestFrame(1, 0, 0, 0), filter: config.PCAPFilter{Port: "2404"}},
		{name: "noninitial fragment", packet: portTestFrame(6, 1024, 2404, 1), filter: config.PCAPFilter{Port: "2404"}},
		{name: "invalid filter", packet: tcp, filter: config.PCAPFilter{Port: "bad"}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := matchFilter(tt.packet, tt.filter); got != tt.want {
				t.Fatalf("matchFilter() = %v, want %v", got, tt.want)
			}
		})
	}

	if matchFilter(tcp[:35], config.PCAPFilter{Port: "2404"}) {
		t.Fatal("truncated transport ports matched")
	}
}

func portTestFrame(protocol byte, srcPort, dstPort uint16, fragmentOffset uint16) []byte {
	frame := make([]byte, 14+20+8)
	frame[12], frame[13] = 0x08, 0x00
	frame[14] = 0x45
	frame[16], frame[17] = 0, 28
	frame[20] = byte(fragmentOffset >> 8)
	frame[21] = byte(fragmentOffset)
	frame[23] = protocol
	frame[26], frame[27], frame[28], frame[29] = 192, 0, 2, 1
	frame[30], frame[31], frame[32], frame[33] = 192, 0, 2, 2
	frame[34], frame[35] = byte(srcPort>>8), byte(srcPort)
	frame[36], frame[37] = byte(dstPort>>8), byte(dstPort)
	return frame
}
