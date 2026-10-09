// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

package pcap

import (
	"bytes"
	"encoding/binary"
	"testing"

	"github.com/tonylturner/containd/pkg/dp/ics/modbus"
)

// tcpEthernetFrame builds an Ethernet+IPv4+TCP frame from 10.0.0.1:49152
// to 10.0.0.2:502, padded to the 60-byte Ethernet minimum like a frame
// captured on the wire.
func tcpEthernetFrame(seq uint32, flags byte, payload []byte) []byte {
	tcp := make([]byte, 20)
	binary.BigEndian.PutUint16(tcp[0:], 49152)
	binary.BigEndian.PutUint16(tcp[2:], 502)
	binary.BigEndian.PutUint32(tcp[4:], seq)
	tcp[12] = 5 << 4
	tcp[13] = flags

	ip := make([]byte, 20)
	ip[0] = 0x45
	binary.BigEndian.PutUint16(ip[2:], uint16(20+20+len(payload)))
	ip[9] = 6
	ip[12], ip[13], ip[14], ip[15] = 10, 0, 0, 1
	ip[16], ip[17], ip[18], ip[19] = 10, 0, 0, 2

	eth := make([]byte, 14)
	binary.BigEndian.PutUint16(eth[12:], 0x0800)

	frame := append(append(append(eth, ip...), tcp...), payload...)
	for len(frame) < 60 {
		frame = append(frame, 0)
	}
	return frame
}

func modbusADU(tid uint16, fc byte, addr, value uint16) []byte {
	adu := make([]byte, 12)
	binary.BigEndian.PutUint16(adu[0:], tid)
	binary.BigEndian.PutUint16(adu[4:], 6)
	adu[6] = 1
	adu[7] = fc
	binary.BigEndian.PutUint16(adu[8:], addr)
	binary.BigEndian.PutUint16(adu[10:], value)
	return adu
}

func TestAnalyzePersistentModbusConnection(t *testing.T) {
	const ack, psh, syn = 0x10, 0x08, 0x02
	read1 := modbusADU(10, 3, 0, 2)
	write := modbusADU(11, 6, 1, 0x1234)
	read2 := modbusADU(12, 3, 0, 2)
	frames := [][]byte{
		tcpEthernetFrame(999, syn, nil),
		tcpEthernetFrame(1000, ack|psh, read1),
		// Padded pure ACK: the padding must not enter the stream.
		tcpEthernetFrame(1012, ack, nil),
		tcpEthernetFrame(1012, ack|psh, write),
		// Retransmission of the write.
		tcpEthernetFrame(1012, ack|psh, write),
		// The last read split across two segments.
		tcpEthernetFrame(1024, ack|psh, read2[:5]),
		tcpEthernetFrame(1029, ack|psh, read2[5:]),
	}

	result, err := Analyze(bytes.NewReader(buildPCAP(frames)), modbus.NewDecoder())
	if err != nil {
		t.Fatalf("Analyze() error: %v", err)
	}
	want := []struct {
		tid     uint16
		fc      uint8
		isWrite bool
	}{{10, 3, false}, {11, 6, true}, {12, 3, false}}
	if len(result.Events) != len(want) {
		t.Fatalf("got %d events, want %d: %+v", len(result.Events), len(want), result.Events)
	}
	for i, w := range want {
		attrs := result.Events[i].Attributes
		if attrs["transaction_id"] != w.tid || attrs["function_code"] != w.fc || attrs["is_write"] != w.isWrite {
			t.Fatalf("event %d = %+v, want tid=%d fc=%d is_write=%v", i, attrs, w.tid, w.fc, w.isWrite)
		}
	}
}
