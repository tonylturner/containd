// SPDX-License-Identifier: Apache-2.0

package dpi

import (
	"net"
	"testing"
	"time"

	"github.com/tonylturner/containd/pkg/dp/flow"
)

type selectableFramer struct {
	mockStreamDecoder
	port       uint16
	enabled    bool
	parseCalls int
}

func (d *selectableFramer) Ports() ([]uint16, []uint16) { return []uint16{d.port}, nil }
func (d *selectableFramer) Supports(*flow.State) bool   { return d.enabled }

func (d *selectableFramer) ParseStream(st *flow.State, v StreamView) (StreamResult, error) {
	d.parseCalls++
	return d.mockStreamDecoder.ParseStream(st, v)
}

func TestFramerPinLifetime(t *testing.T) {
	for _, session := range []bool{false, true} {
		name := "legacy"
		if session {
			name = "session"
		}
		t.Run(name, func(t *testing.T) {
			first := &selectableFramer{port: 502, enabled: true}
			next := &selectableFramer{port: 2404, enabled: true}
			m := NewManager(next, first)
			key := flow.Key{SrcIP: net.ParseIP("10.0.0.1"), DstIP: net.ParseIP("10.0.0.2"), SrcPort: 2404, DstPort: 502, Proto: 6}
			client, server := flow.NewState(key, time.Now()), flow.NewState(key.Reversed(), time.Now())
			c, s := tcpSeg(10, 0), tcpSeg(20, 0)
			if session {
				c, s = sessionSeg("s", ClientToServer, 0, 0), sessionSeg("s", ServerToClient, 0, 0)
			}
			m.Inspect(client, c)
			// A pin is reused, not reselected from Supports or candidate order.
			first.enabled = false
			m.Inspect(server, s)
			if first.parseCalls != 2 || next.parseCalls != 0 {
				t.Fatalf("parse calls: first=%d next=%d", first.parseCalls, next.parseCalls)
			}
			// Failure retains the pin with the failed transport tombstone.
			m.FailStream(client, c, StreamDenied)
			k, _, _ := streamKey(client, c)
			if m.reassembler.framingDecoder(k, "") != first {
				t.Fatal("failure released the connection owner")
			}
			if session {
				m.EndStream("s")
			} else {
				if _, err := m.OnFlowEnd(client); err != nil {
					t.Fatal(err)
				}
				if m.flowFramer(server, s) != first {
					t.Fatal("ending one direction released the peer's pin")
				}
				m.DiscardFlow(server)
			}
			if n, _ := m.reassembler.stats(); n != 0 {
				t.Fatalf("cleanup retained %d streams/pins", n)
			}
			if m.flowFramer(client, c) != next {
				t.Fatal("new stream retained the ended connection's owner")
			}
		})
	}
}

func TestFramerPinCloseAndExpiry(t *testing.T) {
	for _, expire := range []bool{false, true} {
		d := &selectableFramer{port: 502, enabled: true}
		m := NewManager(d)
		st := flow.NewState(flow.Key{Proto: 6, DstPort: 502}, time.Now())
		m.Inspect(st, tcpSeg(10, 0))
		if expire {
			m.reassembler.mu.Lock()
			m.reassembler.streams[st.Key.Hash()].lastUpdate = time.Now().Add(-time.Hour)
			m.reassembler.lastSweep = time.Time{}
			m.reassembler.mu.Unlock()
			// A pure ACK also sweeps, without creating a replacement pin.
			m.Inspect(st, &ParsedPacket{Proto: "tcp"})
		} else {
			if ended, _, err := m.CloseStream(st, &ParsedPacket{Proto: "tcp", TCPFin: true}); !ended || err != nil {
				t.Fatalf("close: ended=%t err=%v", ended, err)
			}
		}
		if n, _ := m.reassembler.stats(); n != 0 {
			t.Fatalf("cleanup retained %d streams/pins (expiry=%t)", n, expire)
		}
	}
}
