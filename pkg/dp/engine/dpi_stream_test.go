// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

package engine

import (
	"encoding/binary"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/tonylturner/containd/pkg/dp/capture"
	"github.com/tonylturner/containd/pkg/dp/events"
	"github.com/tonylturner/containd/pkg/dp/rules"
)

func modbusADU(tid uint16, fc byte, a, b uint16) []byte {
	out := make([]byte, 12)
	binary.BigEndian.PutUint16(out[0:], tid)
	binary.BigEndian.PutUint16(out[4:], 6)
	out[6] = 1
	out[7] = fc
	binary.BigEndian.PutUint16(out[8:], a)
	binary.BigEndian.PutUint16(out[10:], b)
	return out
}

func newModbusInspectEngine(t *testing.T) *Engine {
	t.Helper()
	e, err := New(Config{Capture: capture.Config{Interfaces: []string{"eth0", "eth1"}}, DPIEnabled: true})
	if err != nil {
		t.Fatalf("new engine: %v", err)
	}
	e.LoadRules(rules.Snapshot{
		Default: rules.ActionAllow,
		Firewall: []rules.Entry{{
			ID:        "inspect-modbus",
			Protocols: []rules.Protocol{{Name: "tcp", Port: "502"}},
			ICS:       rules.ICSPredicate{Protocol: "modbus"},
			Action:    rules.ActionAllow,
		}},
	})
	return e
}

func clientSegment(iface string, seq uint32, flags uint8, payload []byte) capture.Packet {
	return capture.Packet{
		Timestamp: time.Now().UTC(),
		Interface: iface,
		SrcIP:     net.ParseIP("172.31.0.5"),
		DstIP:     net.ParseIP("172.30.0.4"),
		SrcPort:   41000,
		DstPort:   502,
		Proto:     6,
		Transport: "tcp",
		Payload:   payload,
		TCPSeq:    seq,
		HasTCPSeq: true,
		TCPFlags:  flags,
	}
}

func modbusEventsOldestFirst(e *Engine) []events.Event {
	var out []events.Event
	list := e.Events().List(0)
	for i := len(list) - 1; i >= 0; i-- {
		if list[i].Proto == "modbus" {
			out = append(out, list[i])
		}
	}
	return out
}

// TestHandlePacketPersistentModbusConnection replays one TCP connection
// carrying FC3 -> FC6 -> FC3, with every segment captured on both the
// ingress and egress interface concurrently, as AF_PACKET delivers a
// forwarded packet.
func TestHandlePacketPersistentModbusConnection(t *testing.T) {
	e := newModbusInspectEngine(t)
	const ack, psh = 0x10, 0x08
	segments := []capture.Packet{
		clientSegment("", 5000, capture.TCPFlagSYN, nil),
		clientSegment("", 5000, ack|psh, modbusADU(10, 3, 0, 2)),
		clientSegment("", 5012, ack|psh, modbusADU(11, 6, 1, 0x1234)),
		clientSegment("", 5024, ack|psh, modbusADU(12, 3, 0, 2)),
	}
	for _, seg := range segments {
		var wg sync.WaitGroup
		for _, iface := range []string{"eth1", "eth0"} {
			pkt := seg
			pkt.Interface = iface
			wg.Add(1)
			go func() {
				defer wg.Done()
				e.handlePacket(pkt)
			}()
		}
		wg.Wait()
	}

	got := modbusEventsOldestFirst(e)
	want := []struct {
		tid     uint16
		fc      uint8
		isWrite bool
	}{{10, 3, false}, {11, 6, true}, {12, 3, false}}
	if len(got) != len(want) {
		t.Fatalf("got %d modbus events, want %d: %+v", len(got), len(want), got)
	}
	for i, w := range want {
		a := got[i].Attributes
		if a["transaction_id"] != w.tid || a["function_code"] != w.fc || a["is_write"] != w.isWrite {
			t.Fatalf("event %d = %+v, want tid=%d fc=%d is_write=%v", i, a, w.tid, w.fc, w.isWrite)
		}
	}
}

// TestHandlePacketLateSYNCopyDoesNotDuplicate reproduces the live smoke
// ordering: the egress capture of the SYN is processed after the ingress
// capture already decoded the first request. The request must be reported
// once.
func TestHandlePacketLateSYNCopyDoesNotDuplicate(t *testing.T) {
	e := newModbusInspectEngine(t)
	const ack, psh = 0x10, 0x08
	syn := clientSegment("", 7000, capture.TCPFlagSYN, nil)
	write := clientSegment("", 7000, ack|psh, modbusADU(1, 6, 1, 0x1234))
	for _, step := range []struct {
		iface string
		pkt   capture.Packet
	}{{"eth1", syn}, {"eth1", write}, {"eth0", syn}, {"eth0", write}} {
		pkt := step.pkt
		pkt.Interface = step.iface
		e.handlePacket(pkt)
	}
	if got := modbusEventsOldestFirst(e); len(got) != 1 {
		t.Fatalf("got %d modbus events, want 1: %+v", len(got), got)
	}
}
