// SPDX-License-Identifier: Apache-2.0

package engine

import (
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/tonylturner/containd/pkg/dp/capture"
	"github.com/tonylturner/containd/pkg/dp/rules"
	"github.com/tonylturner/containd/pkg/dp/session"
)

// Exercise production decoding, policy, inventory and event retention, with a
// full telemetry ring. Each operation is one packet, not one transaction.
func BenchmarkIECMonitorPackets(b *testing.B) {
	for _, mode := range []string{"monitor", "enforce"} {
		for _, sessions := range []int{1, 8, 32, 128} {
			b.Run(fmt.Sprintf("%s/sessions=%d", mode, sessions), func(b *testing.B) {
				_, exchange := newIECPerfExchange(b, mode, sessions)
				for i := range 4096 {
					exchange(i)
				}
				b.ReportAllocs()
				b.ResetTimer()
				for i := range b.N {
					exchange(i)
				}
			})
		}
	}
}

// Keep the benchmark honest: all packets must remain decoded, and monitor
// observations (including the unmatched enforcing-policy decision) must survive.
func TestIECMonitorPacketExchange(t *testing.T) {
	for _, mode := range []string{"monitor", "enforce"} {
		t.Run(mode, func(t *testing.T) {
			e, exchange := newIECPerfExchange(t, mode, 32)
			for i := range 8192 {
				exchange(i)
			}
			for _, s := range e.iec.sessions {
				if s.state != iecEstablished || s.stopParse || s.inspectionLost {
					t.Fatalf("session stopped decoding: %+v", s)
				}
			}
			var decoded int64
			for _, stat := range e.ProtoStats() {
				if stat.Protocol == "iec104" {
					decoded = stat.EventCount
				}
			}
			if decoded != 8192+2*32 {
				t.Fatalf("decoded %d events, want %d", decoded, 8192+2*32)
			}
			var shadow, unmatched int
			for _, ev := range e.Events().List(0) {
				switch ev.Kind {
				case "anomaly":
					typ, _ := ev.Attributes["anomaly_type"].(string)
					if strings.HasPrefix(typ, "iec104_") {
						t.Fatalf("invalid APCI exchange: %+v", ev)
					}
				case "alert":
					t.Fatalf("nonconformant exchange: %+v", ev)
				case "ics.decision":
					switch ev.Attributes["decision"] {
					case decisionWouldAllow:
						shadow++
					case decisionWouldDrop:
						unmatched++
					}
				}
			}
			if mode == "monitor" {
				if shadow == 0 || unmatched == 0 {
					t.Fatalf("monitor decisions lost: shadow=%d unmatched=%d", shadow, unmatched)
				}
				counts := e.ShadowCounters()
				if len(counts.Rules) != 1 || counts.Rules[0].ShadowMatches != 8192+2*32 {
					t.Fatalf("monitor observation count: %+v", counts)
				}
			} else if shadow != 0 || unmatched != 0 {
				t.Fatal("enforcing safe-read traffic denied")
			}
		})
	}
}

func newIECPerfExchange(tb testing.TB, mode string, sessions int) (*Engine, func(int)) {
	tb.Helper()
	e, err := New(Config{DPIEnabled: true, DPIMode: mode, ResetInjector: &session.Fake{}})
	if err != nil {
		tb.Fatal(err)
	}
	snap := rules.Snapshot{Default: rules.ActionDeny, DPIMode: mode, Firewall: []rules.Entry{{
		ID: "inspection", Action: rules.ActionAllow,
		Protocols: []rules.Protocol{{Name: "tcp", Port: "2404"}},
		ICS:       rules.ICSPredicate{Protocol: "iec104", Mode: mode, ReadOnly: mode == "enforce"},
	}}}
	if mode == "monitor" {
		snap.Firewall = append(snap.Firewall, rules.Entry{ID: "l4", Action: rules.ActionAllow,
			Protocols: []rules.Protocol{{Name: "tcp", Port: "2404"}}})
	}
	if err := e.ApplyRules(context.Background(), snap); err != nil {
		tb.Fatal(err)
	}
	now := time.Now()
	e.iec.now = func() time.Time { return now }
	type exchange struct {
		packets [4]capture.Packet
		step    int
		ns      uint16
		seq     [2]uint32
	}
	flows := make([]exchange, sessions)
	var token uint32
	send := func(p capture.Packet) {
		token++
		p.Token = capture.NewToken(1, token)
		if d := e.HandlePacket(p); d.Action != capture.Repeat {
			tb.Fatalf("packet rejected: %+v", d)
		}
	}
	for i := range flows {
		f := &flows[i]
		client, server := net.IPv4(192, 0, 2, 1), net.IPv4(192, 0, 2, 2)
		port := uint16(40000 + i)
		c := capture.Packet{Timestamp: now, SrcIP: client, DstIP: server, SrcPort: port, DstPort: 2404,
			Proto: 6, Transport: "tcp", TCP: capture.TCPMeta{Valid: true},
			Queue: policyQueue(client, server, port, 2404, false)}
		s := c
		s.SrcIP, s.DstIP, s.SrcPort, s.DstPort = server, client, 2404, port
		s.Queue = policyQueue(client, server, port, 2404, true)
		c.TCP.Flags, c.TCP.Seq = capture.TCPFlagSYN, 100
		markHandshake(&c)
		send(c)
		s.TCP.Flags, s.TCP.Seq, s.TCP.Ack = capture.TCPFlagSYN|capture.TCPFlagACK, 200, 101
		markHandshake(&s)
		send(s)
		c.TCP.Flags, c.TCP.Seq, c.TCP.Ack = capture.TCPFlagACK, 101, 201
		send(c)
		c.Payload, s.Payload = startdtAct, startdtCon
		s.TCP.Flags, s.TCP.Seq, s.TCP.Ack = capture.TCPFlagACK, 201, 107
		send(c)
		send(s)
		c.Mark, s.Mark = 0, 0
		f.seq = [2]uint32{107, 207}
		c.Payload, s.Payload = apdu(102, 5, 1, 1), apdu(1, 5, 1, 1, 1)
		f.packets = [4]capture.Packet{c, s, c, s}
		f.packets[2].Payload, f.packets[3].Payload = apciS(0), apciS(0)
	}
	return e, func(i int) {
		f := &flows[i%sessions]
		step := f.step % 4
		p := f.packets[step]
		dir := step % 2
		p.TCP.Seq, p.TCP.Ack = f.seq[dir], f.seq[1-dir]
		if step < 2 {
			binary.LittleEndian.PutUint16(p.Payload[2:4], f.ns<<1)
			nr := f.ns
			if dir == 1 {
				nr++
			}
			binary.LittleEndian.PutUint16(p.Payload[4:6], nr<<1)
		} else {
			binary.LittleEndian.PutUint16(p.Payload[4:6], (f.ns+1)<<1)
		}
		send(p)
		f.seq[dir] += uint32(len(p.Payload))
		f.step++
		if step == 3 {
			f.ns = (f.ns + 1) % 32768
		}
	}
}
