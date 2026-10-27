// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 containd Authors

package pcap

import (
	"bytes"
	"encoding/binary"
	"testing"

	"github.com/tonylturner/containd/pkg/dp/flow"
	"github.com/tonylturner/containd/pkg/dp/ics/modbus"
)

func orientedModbusFrame(reverse bool, clientPort, serverPort uint16, seq uint32, flags byte, payload []byte) []byte {
	f := tcpEthernetFrame(seq, flags, payload)
	binary.BigEndian.PutUint16(f[34:], clientPort)
	binary.BigEndian.PutUint16(f[36:], serverPort)
	if reverse {
		binary.BigEndian.PutUint16(f[34:], serverPort)
		binary.BigEndian.PutUint16(f[36:], clientPort)
		copy(f[26:30], []byte{10, 0, 0, 2})
		copy(f[30:34], []byte{10, 0, 0, 1})
	}
	return f
}

func TestAnalyzeModbusOrientation(t *testing.T) {
	const syn, ack, psh = 0x02, 0x10, 0x08
	for _, tc := range []struct {
		name                              string
		clientPort, serverPort            uint16
		handshake, synAckOnly, replyFirst bool
	}{
		{"source 502", 502, 41000, true, false, false},
		{"both 502", 502, 502, true, false, false},
		{"ordinary handshake", 41000, 502, true, false, false},
		{"SYN-ACK only source 502", 502, 41000, true, true, false},
		{"SYN-ACK only both 502", 502, 502, true, true, false},
		{"midstream request first", 41000, 502, false, false, false},
		{"midstream reply first", 41000, 502, false, false, true},
		{"midstream ambiguous first seen", 502, 502, false, false, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			frame := func(reverse bool, seq uint32, flags byte, payload []byte) []byte {
				return orientedModbusFrame(reverse, tc.clientPort, tc.serverPort, seq, flags, payload)
			}
			var frames [][]byte
			if tc.handshake {
				if !tc.synAckOnly {
					frames = append(frames, frame(false, 99, syn, nil))
				}
				frames = append(frames, frame(true, 499, syn|ack, nil))
			}
			req := frame(false, 100, ack|psh, modbusADU(1, 3, 10, 2))
			reply := frame(true, 500, ack|psh, []byte{0, 1, 0, 0, 0, 7, 1, 3, 4, 0, 10, 0, 11})
			if tc.replyFirst {
				frames = append(frames, reply, req)
			} else {
				frames = append(frames, req, reply)
			}
			frames = append(frames, frame(true, 513, ack|psh, []byte{0, 2, 0, 0, 0, 3, 1, 0x83, 2}))
			res, err := Analyze(bytes.NewReader(buildPCAP(frames)), modbus.NewDecoder())
			if err != nil {
				t.Fatal(err)
			}
			kinds := []string{"request", "response", "exception"}
			if tc.replyFirst {
				kinds[0], kinds[1] = kinds[1], kinds[0]
			}
			if len(res.Events) != len(kinds) {
				t.Fatalf("events=%+v", res.Events)
			}
			for i, ev := range res.Events {
				if ev.Kind != kinds[i] {
					t.Fatalf("event %d=%+v want %s", i, ev, kinds[i])
				}
				k, ok := flow.ParseKey(ev.FlowID)
				wantDir := flow.DirReverse
				if ev.Kind == "request" {
					wantDir = flow.DirForward
				}
				if !ok || k.Dir != wantDir {
					t.Fatalf("event orientation: %+v", ev)
				}
				if ev.Kind == "request" && (ev.Attributes["address"] != uint16(10) || ev.Attributes["quantity"] != uint16(2)) {
					t.Fatalf("lost request spans: %+v", ev)
				}
				if ev.Kind == "response" && ev.Attributes["byte_count"] != uint8(4) {
					t.Fatalf("lost response fields: %+v", ev)
				}
			}
			if len(res.Flows) != 2 {
				t.Fatalf("flows=%+v", res.Flows)
			}
		})
	}
}

func TestAnalyzeHandshakeOverridesMidstreamHint(t *testing.T) {
	const syn, ack, psh = 0x02, 0x10, 0x08
	// The initial source-502 packet is only a port hint. A subsequent observed
	// handshake proves that the same sender is actually the opener.
	frames := [][]byte{
		orientedModbusFrame(false, 502, 41000, 10, ack|psh, modbusADU(1, 6, 10, 1)),
		orientedModbusFrame(true, 502, 41000, 20, ack|psh, modbusADU(1, 6, 10, 1)),
		orientedModbusFrame(false, 502, 41000, 99, syn, nil),
		orientedModbusFrame(true, 502, 41000, 499, syn|ack, nil),
		orientedModbusFrame(false, 502, 41000, 100, ack|psh, modbusADU(2, 3, 10, 2)),
		orientedModbusFrame(true, 502, 41000, 500, ack|psh, []byte{0, 2, 0, 0, 0, 5, 1, 3, 2, 0, 42}),
	}
	res, err := Analyze(bytes.NewReader(buildPCAP(frames)), modbus.NewDecoder())
	if err != nil {
		t.Fatal(err)
	}
	kinds := []string{"response", "request", "request", "response"}
	if len(res.Events) != len(kinds) {
		t.Fatalf("events=%+v", res.Events)
	}
	for i, ev := range res.Events {
		if ev.Kind != kinds[i] {
			t.Fatalf("event %d=%+v want %s", i, ev, kinds[i])
		}
	}
}
