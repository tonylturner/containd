// SPDX-License-Identifier: Apache-2.0

package pcap

import (
	"bytes"
	"encoding/binary"
	"testing"

	"github.com/tonylturner/containd/pkg/dp/ics/cip"
	"github.com/tonylturner/containd/pkg/dp/ics/iec104"
	"github.com/tonylturner/containd/pkg/dp/ics/modbus"
)

func TestIdentificationENIPImplicitPort(t *testing.T) {
	// ListServices response: one communications-service item, version 1.
	payload := make([]byte, 24+2+4+20)
	binary.LittleEndian.PutUint16(payload, 4)
	binary.LittleEndian.PutUint16(payload[2:], 26)
	binary.LittleEndian.PutUint16(payload[24:], 1)
	binary.LittleEndian.PutUint16(payload[26:], 0x100)
	binary.LittleEndian.PutUint16(payload[28:], 20)
	binary.LittleEndian.PutUint16(payload[30:], 1)
	copy(payload[34:], "Communications")

	for _, tc := range []struct {
		name        string
		src, dst    uint16
		wantBinding string
	}{
		{"source", 2222, 49152, "observation"},
		{"destination", 49152, 2222, "observation"},
		{"source-over-encapsulation", 2222, 44818, "observation"},
		{"destination-over-encapsulation", 44818, 2222, "observation"},
		{"encapsulation", 44818, 49152, "legacy"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			// Reuse the Ethernet/IP builder, replacing its TCP segment with UDP.
			frame := tcpEthernetFrame(0, 0, nil)[:34]
			frame[23] = 17
			binary.BigEndian.PutUint16(frame[16:], uint16(20+8+len(payload)))
			udp := make([]byte, 8)
			binary.BigEndian.PutUint16(udp, tc.src)
			binary.BigEndian.PutUint16(udp[2:], tc.dst)
			binary.BigEndian.PutUint16(udp[4:], uint16(8+len(payload)))
			frame = append(append(frame, udp...), payload...)
			result, err := Analyze(bytes.NewReader(buildPCAP([][]byte{frame})), cip.NewDecoder())
			if err != nil {
				t.Fatal(err)
			}
			if len(result.Identifications) != 1 {
				t.Fatalf("identifications: %+v", result.Identifications)
			}
			id := result.Identifications[0]
			if a := id.Attributes; a["protocol"] != "cip" || a["identification_state"] != "confirmed" || a["binding"] != tc.wantBinding {
				t.Errorf("identification: %+v", id)
			}
			encapsulations := 0
			for _, ev := range result.Events {
				if ev.Proto != "cip" || ev.Attributes["enip_command"] != "ListServices" {
					continue
				}
				encapsulations++
				if (ev.Attributes["observation_only"] == true) != (tc.wantBinding == "observation") ||
					ev.Connection == nil || ev.Connection.Key != id.Key {
					t.Errorf("encapsulation batch event: %+v", ev)
				}
			}
			if encapsulations != 1 {
				t.Fatalf("encapsulation events=%d, want 1: %+v", encapsulations, result.Events)
			}
		})
	}
}

func TestIdentificationIECSessionOwnership(t *testing.T) {
	for _, tc := range []struct {
		name         string
		client, port uint16
		synack       bool
		protocol     string
		binding      string
		events       int
	}{
		{"IEC-session", 49152, 2404, true, "iec104", "legacy", 2},
		{"IEC-source-port", 2404, 12404, true, "iec104", "observation", 2},
		{"IEC-no-SYN-ACK", 49152, 2404, false, "iec104", "observation", 2},
		{"modbus-IEC-source", 2404, 502, true, "modbus", "observation", 2},
		// The server port owns framing; Modbus content beside an IEC104
		// owner must be passively decoded in both directions.
		{"modbus-IEC-session", 502, 2404, true, "modbus", "observation", 2},
		{"IEC-session-Modbus-source", 502, 2404, true, "iec104", "legacy", 2},
	} {
		t.Run(tc.name, func(t *testing.T) {
			frame := func(reverse bool, seq uint32, flags byte, payload []byte) []byte {
				f := orientedModbusFrame(reverse, tc.client, tc.port, seq, flags, payload)
				if reverse {
					binary.BigEndian.PutUint32(f[42:], 100)
				}
				return f
			}
			frames := [][]byte{frame(false, 99, 2, nil)}
			if tc.synack {
				frames = append(frames, frame(true, 499, 0x12, nil))
			}
			payload := []byte{0x68, 4, 7, 0, 0, 0, 0x68, 4, 0x43, 0, 0, 0}
			if tc.protocol == "modbus" {
				payload = modbusADU(1, 3, 0, 2)
			}
			frames = append(frames, frame(false, 100, 0x18, payload))
			if tc.protocol == "modbus" {
				frames = append(frames, frame(true, 500, 0x18, []byte{0, 1, 0, 0, 0, 7, 1, 3, 4, 0, 10, 0, 11}))
			}
			result, err := Analyze(bytes.NewReader(buildPCAP(frames)), modbus.NewDecoder(), iec104.NewDecoder())
			if err != nil {
				t.Fatal(err)
			}
			if len(result.Identifications) != 1 {
				t.Fatalf("identifications: %+v", result.Identifications)
			}
			if a := result.Identifications[0].Attributes; a["protocol"] != tc.protocol || a["identification_state"] != "confirmed" || a["binding"] != tc.binding {
				t.Errorf("identification: %+v", a)
			}
			count := 0
			for _, ev := range result.Events {
				if ev.Proto == tc.protocol && ev.Kind != "malformed" {
					count++
					if (ev.Attributes["observation_only"] == true) != (tc.binding == "observation") {
						t.Errorf("marker: %+v", ev)
					}
				}
			}
			if count != tc.events {
				t.Fatalf("decoded=%d want %d: %+v", count, tc.events, result.Events)
			}
		})
	}
}
