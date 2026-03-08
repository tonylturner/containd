// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

package pcap

import (
	"bytes"
	"encoding/binary"
	"testing"
	"time"

	"github.com/tonylturner/containd/pkg/dp/ics/modbus"
)

// buildPCAP constructs a minimal PCAP file in memory containing the given
// Ethernet frames.
func buildPCAP(frames [][]byte) []byte {
	var buf bytes.Buffer
	// Global header: magic, version 2.4, thiszone=0, sigfigs=0, snaplen=65535, linktype=1 (Ethernet).
	header := make([]byte, 24)
	binary.LittleEndian.PutUint32(header[0:], 0xa1b2c3d4)
	binary.LittleEndian.PutUint16(header[4:], 2)
	binary.LittleEndian.PutUint16(header[6:], 4)
	binary.LittleEndian.PutUint32(header[8:], 0)
	binary.LittleEndian.PutUint32(header[12:], 0)
	binary.LittleEndian.PutUint32(header[16:], 65535)
	binary.LittleEndian.PutUint32(header[20:], 1)
	buf.Write(header)

	ts := time.Date(2025, 1, 15, 10, 0, 0, 0, time.UTC)
	for i, frame := range frames {
		rec := make([]byte, 16)
		sec := uint32(ts.Unix()) + uint32(i)
		binary.LittleEndian.PutUint32(rec[0:], sec)
		binary.LittleEndian.PutUint32(rec[4:], 0) // usec
		binary.LittleEndian.PutUint32(rec[8:], uint32(len(frame)))
		binary.LittleEndian.PutUint32(rec[12:], uint32(len(frame)))
		buf.Write(rec)
		buf.Write(frame)
	}
	return buf.Bytes()
}

// buildModbusEthernetFrame constructs a minimal Ethernet+IPv4+TCP frame
// containing a valid Modbus/TCP request (function code 3 = Read Holding Registers).
func buildModbusEthernetFrame() []byte {
	// Modbus MBAP + PDU: transaction=1, protocol=0, length=6, unit=1, fc=3, addr=0, qty=10.
	mbap := make([]byte, 12)
	binary.BigEndian.PutUint16(mbap[0:], 1)   // transaction ID
	binary.BigEndian.PutUint16(mbap[2:], 0)   // protocol ID
	binary.BigEndian.PutUint16(mbap[4:], 6)   // length (unit + fc + 4 PDU bytes)
	mbap[6] = 1                                // unit ID
	mbap[7] = 3                                // function code (Read Holding Registers)
	binary.BigEndian.PutUint16(mbap[8:], 0)   // start address
	binary.BigEndian.PutUint16(mbap[10:], 10) // quantity

	// TCP header (20 bytes, minimal).
	tcp := make([]byte, 20)
	binary.BigEndian.PutUint16(tcp[0:], 49152) // src port
	binary.BigEndian.PutUint16(tcp[2:], 502)   // dst port (Modbus)
	tcp[12] = 5 << 4                           // data offset = 5 (20 bytes)

	// IPv4 header (20 bytes, minimal).
	ip := make([]byte, 20)
	ip[0] = 0x45 // version=4, IHL=5
	totalLen := 20 + 20 + len(mbap)
	binary.BigEndian.PutUint16(ip[2:], uint16(totalLen))
	ip[9] = 6 // protocol = TCP
	// src IP: 10.0.0.1
	ip[12], ip[13], ip[14], ip[15] = 10, 0, 0, 1
	// dst IP: 10.0.0.2
	ip[16], ip[17], ip[18], ip[19] = 10, 0, 0, 2

	// Ethernet header (14 bytes).
	eth := make([]byte, 14)
	// dst MAC: 00:00:00:00:00:02
	eth[5] = 2
	// src MAC: 00:00:00:00:00:01
	eth[11] = 1
	// EtherType: IPv4 (0x0800)
	binary.BigEndian.PutUint16(eth[12:], 0x0800)

	var frame []byte
	frame = append(frame, eth...)
	frame = append(frame, ip...)
	frame = append(frame, tcp...)
	frame = append(frame, mbap...)
	return frame
}

func TestAnalyzeModbusPacket(t *testing.T) {
	frame := buildModbusEthernetFrame()
	pcapData := buildPCAP([][]byte{frame})

	decoder := modbus.NewDecoder()
	result, err := Analyze(bytes.NewReader(pcapData), decoder)
	if err != nil {
		t.Fatalf("Analyze() error: %v", err)
	}

	if result.PacketCount != 1 {
		t.Errorf("PacketCount = %d, want 1", result.PacketCount)
	}
	if result.ByteCount != len(frame) {
		t.Errorf("ByteCount = %d, want %d", result.ByteCount, len(frame))
	}
	if len(result.Events) == 0 {
		t.Fatal("expected at least one event from modbus decoder")
	}

	ev := result.Events[0]
	if ev.Proto != "modbus" {
		t.Errorf("event Proto = %q, want %q", ev.Proto, "modbus")
	}
	if ev.Kind != "request" {
		t.Errorf("event Kind = %q, want %q", ev.Kind, "request")
	}

	fc, ok := ev.Attributes["function_code"]
	if !ok {
		t.Fatal("expected function_code attribute")
	}
	if fc != uint8(3) {
		t.Errorf("function_code = %v, want 3", fc)
	}

	if result.Protocols["modbus"] != 1 {
		t.Errorf("Protocols[modbus] = %d, want 1", result.Protocols["modbus"])
	}

	if len(result.Flows) != 1 {
		t.Errorf("len(Flows) = %d, want 1", len(result.Flows))
	}
	if len(result.Flows) > 0 {
		f := result.Flows[0]
		if f.Protocol != "tcp" {
			t.Errorf("flow Protocol = %q, want %q", f.Protocol, "tcp")
		}
		if f.Packets != 1 {
			t.Errorf("flow Packets = %d, want 1", f.Packets)
		}
		if f.Events != 1 {
			t.Errorf("flow Events = %d, want 1", f.Events)
		}
	}
}

func TestAnalyzeEmptyPCAP(t *testing.T) {
	// A valid PCAP with no packets (just the global header).
	pcapData := buildPCAP(nil)

	decoder := modbus.NewDecoder()
	result, err := Analyze(bytes.NewReader(pcapData), decoder)
	if err != nil {
		t.Fatalf("Analyze() error: %v", err)
	}

	if result.PacketCount != 0 {
		t.Errorf("PacketCount = %d, want 0", result.PacketCount)
	}
	if result.ByteCount != 0 {
		t.Errorf("ByteCount = %d, want 0", result.ByteCount)
	}
	if len(result.Events) != 0 {
		t.Errorf("len(Events) = %d, want 0", len(result.Events))
	}
	if len(result.Flows) != 0 {
		t.Errorf("len(Flows) = %d, want 0", len(result.Flows))
	}
	if result.Duration != 0 {
		t.Errorf("Duration = %v, want 0", result.Duration)
	}
}

func TestAnalyzePacketCounting(t *testing.T) {
	frame1 := buildModbusEthernetFrame()
	frame2 := buildModbusEthernetFrame()

	pcapData := buildPCAP([][]byte{frame1, frame2})

	decoder := modbus.NewDecoder()
	result, err := Analyze(bytes.NewReader(pcapData), decoder)
	if err != nil {
		t.Fatalf("Analyze() error: %v", err)
	}

	if result.PacketCount != 2 {
		t.Errorf("PacketCount = %d, want 2", result.PacketCount)
	}
	expectedBytes := len(frame1) + len(frame2)
	if result.ByteCount != expectedBytes {
		t.Errorf("ByteCount = %d, want %d", result.ByteCount, expectedBytes)
	}
	if len(result.Events) != 2 {
		t.Errorf("len(Events) = %d, want 2", len(result.Events))
	}
	if result.Duration != 1*time.Second {
		t.Errorf("Duration = %v, want 1s", result.Duration)
	}
	// Both packets go to the same 5-tuple, so one flow.
	if len(result.Flows) != 1 {
		t.Errorf("len(Flows) = %d, want 1", len(result.Flows))
	}
	if len(result.Flows) > 0 && result.Flows[0].Packets != 2 {
		t.Errorf("flow Packets = %d, want 2", result.Flows[0].Packets)
	}
}

func TestAnalyzeRejectsPacketLargerThanSnaplen(t *testing.T) {
	var buf bytes.Buffer

	// Global header with snaplen=64.
	header := make([]byte, 24)
	binary.LittleEndian.PutUint32(header[0:], 0xa1b2c3d4)
	binary.LittleEndian.PutUint16(header[4:], 2)
	binary.LittleEndian.PutUint16(header[6:], 4)
	binary.LittleEndian.PutUint32(header[16:], 64)
	binary.LittleEndian.PutUint32(header[20:], 1)
	buf.Write(header)

	// Record claims inclLen=128 (larger than snaplen).
	rec := make([]byte, 16)
	binary.LittleEndian.PutUint32(rec[8:], 128)
	binary.LittleEndian.PutUint32(rec[12:], 128)
	buf.Write(rec)

	if _, err := Analyze(bytes.NewReader(buf.Bytes())); err == nil {
		t.Fatal("Analyze() error = nil, want non-nil for packet larger than snaplen")
	}
}

func TestAnalyzeRejectsPacketLargerThanMaximum(t *testing.T) {
	var buf bytes.Buffer

	// Global header with large snaplen so only the max record guard triggers.
	header := make([]byte, 24)
	binary.LittleEndian.PutUint32(header[0:], 0xa1b2c3d4)
	binary.LittleEndian.PutUint16(header[4:], 2)
	binary.LittleEndian.PutUint16(header[6:], 4)
	binary.LittleEndian.PutUint32(header[16:], maxPCAPRecordSize+1)
	binary.LittleEndian.PutUint32(header[20:], 1)
	buf.Write(header)

	rec := make([]byte, 16)
	binary.LittleEndian.PutUint32(rec[8:], maxPCAPRecordSize+1)
	binary.LittleEndian.PutUint32(rec[12:], maxPCAPRecordSize+1)
	buf.Write(rec)

	if _, err := Analyze(bytes.NewReader(buf.Bytes())); err == nil {
		t.Fatal("Analyze() error = nil, want non-nil for oversized packet record")
	}
}
