// SPDX-License-Identifier: Apache-2.0

package engine

import (
	"encoding/binary"
	"github.com/tonylturner/containd/pkg/dp/capture"
	"github.com/tonylturner/containd/pkg/dp/ics/eventfields"
	"github.com/tonylturner/containd/pkg/dp/rules"
	"strconv"
	"testing"
	"time"
)

func observationTrace(port uint16, iec bool) []capture.Packet {
	a := clientSegment("", 101, capture.TCPFlagSYN, nil)
	a.DstPort, a.HasMark, a.Mark = port, false, 0
	b := a
	b.SrcIP, b.DstIP, b.SrcPort, b.DstPort = a.DstIP, a.SrcIP, port, a.SrcPort
	b.TCP.Seq, b.TCP.Ack, b.TCP.Flags = 500, 101, capture.TCPFlagSYN|capture.TCPFlagACK
	c, d := a, b
	c.TCP.Seq, c.TCP.Flags, c.TCP.Ack = 101, capture.TCPFlagACK, 501
	d.TCP.Seq, d.TCP.Flags, d.TCP.Ack = 501, capture.TCPFlagACK, 101
	c.Payload, d.Payload = modbusADU(1, 3, 0, 2), []byte{0, 1, 0, 0, 0, 7, 1, 3, 4, 0, 1, 0, 2}
	if iec {
		c.Payload, d.Payload = startdtAct, startdtCon
	}
	out := []capture.Packet{a, b, c, d}
	if iec {
		c.TCP.Seq += uint32(len(c.Payload))
		d.TCP.Seq += uint32(len(d.Payload))
		c.Payload, d.Payload = apdu(100, 6, 1, 0, 20), apdu(1, 3, 1, 1001, 1)
		out = append(out, c, d)
	}
	at := time.Unix(1800000000, 0)
	for i := range out {
		out[i].Timestamp = at.Add(time.Duration(i) * time.Millisecond)
	}
	return out
}

func TestObservationAlternatePorts(t *testing.T) {
	for _, tc := range []struct {
		port  uint16
		proto string
		iec   bool
	}{{1502, "modbus", false}, {12404, "iec104", true}, {502, "modbus", false}, {2404, "iec104", true}} {
		t.Run(tc.proto+strconv.Itoa(int(tc.port)), func(t *testing.T) {
			e, err := New(Config{Capture: capture.Config{Interfaces: []string{"eth0"}}, DPIEnabled: true})
			if err != nil {
				t.Fatal(err)
			}
			defer func() { e.observation.observer.Drain(); e.observation.syncMetrics() }()
			e.LoadRules(rules.Snapshot{Default: rules.ActionDeny, Firewall: []rules.Entry{{ID: "scope", ICS: rules.ICSPredicate{Protocol: tc.proto, Mode: "enforce"}, Action: rules.ActionDeny}}})
			if tc.port == 502 || tc.port == 2404 {
				e.LoadRules(rules.Snapshot{Default: rules.ActionAllow})
			}
			for _, pkt := range observationTrace(tc.port, tc.iec) {
				if d := e.HandlePacket(pkt); d.Action != capture.Accept {
					t.Fatalf("%+v", d)
				}
			}
			ids, req, resp := 0, 0, 0
			for _, ev := range e.Events().List(0) {
				if ev.Proto == "identify" {
					ids++
					if ev.Attributes[eventfields.KeyBinding] != "observation" || ev.Attributes[eventfields.KeyIdentificationState] != "confirmed" {
						t.Fatalf("%+v", ev)
					}
				}
				if ev.Proto != tc.proto || ev.Attributes[eventfields.KeyObservationOnly] != true {
					continue
				}
				if tc.iec {
					if ev.Attributes["direction"] == "request" {
						req++
					}
					if ev.Attributes["direction"] == "response" {
						resp++
					}
				} else {
					if ev.Kind == "request" {
						req++
					}
					if ev.Kind == "response" {
						resp++
					}
				}
			}
			if ids != 1 || req == 0 || resp == 0 {
				t.Fatalf("ids=%d req=%d resp=%d events=%+v", ids, req, resp, e.Events().List(0))
			}
		})
	}
}

func TestObservationUDPExplicitLayer(t *testing.T) {
	e := newObservationEngine(t)
	e.LoadRules(rules.Snapshot{Default: rules.ActionAllow, IDS: rules.IDSConfig{Enabled: true}})
	packet := observationTrace(2222, false)[0]
	packet.Proto, packet.Transport, packet.TCP = 17, "udp", capture.TCPMeta{}
	packet.Payload = make([]byte, 24)
	packet.Payload[0] = 4 // ENIP ListServices request.
	e.HandlePacket(packet)
	reply := packet
	reply.SrcIP, reply.DstIP, reply.SrcPort, reply.DstPort = packet.DstIP, packet.SrcIP, packet.DstPort, packet.SrcPort
	body := append([]byte{1, 0, 0, 1, 20, 0, 1, 0}, make([]byte, 18)...)
	reply.Payload = make([]byte, 24+len(body))
	reply.Payload[0] = 4
	binary.LittleEndian.PutUint16(reply.Payload[2:], uint16(len(body)))
	copy(reply.Payload[24:], body)
	e.HandlePacket(reply)
	decoded, identities := 0, 0
	for _, event := range e.Events().List(0) {
		if event.Proto == "identify" {
			identities++
			if event.Attributes["binding"] != "observation" {
				t.Fatalf("implicit I/O incorrectly claimed ENIP: %+v", event)
			}
		}
		if event.Proto == "cip" && event.Attributes["observation_only"] == true {
			decoded++
			if event.Attributes["enip_command"] == nil {
				t.Fatalf("implicit decoder selected: %+v", event)
			}
		}
	}
	if decoded != 2 || identities != 1 {
		t.Fatalf("decoded=%d identities=%d", decoded, identities)
	}
}
