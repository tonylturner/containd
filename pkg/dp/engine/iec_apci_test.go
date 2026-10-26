// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 containd Authors

package engine

import (
	"encoding/binary"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/tonylturner/containd/pkg/dp/anomaly"
	"github.com/tonylturner/containd/pkg/dp/capture"
	"github.com/tonylturner/containd/pkg/dp/dpi"
	"github.com/tonylturner/containd/pkg/dp/events"
	"github.com/tonylturner/containd/pkg/dp/ics/iec104"
	"github.com/tonylturner/containd/pkg/dp/rules"
)

type apciAllowPolicy struct{ *fakePolicy }

func (apciAllowPolicy) EvaluateIEC104(rules.EvalContext) (rules.Action, *rules.Entry) {
	return rules.ActionAllow, &rules.Entry{ID: "allow", Action: rules.ActionAllow}
}

func newAPCIHarness(t *testing.T, mode string) *iecHarness {
	t.Helper()
	h := newIECHarness(t, mode)
	h.e.dpiMgr = dpi.NewManager(iec104.NewDecoder())
	h.e.iec.dpi = h.e.dpiMgr
	h.e.iec.newPolicy = func(*rules.Snapshot) iecPolicy { return apciAllowPolicy{h.policy} }
	h.e.LoadRules(iecSnapshot(mode))
	return h
}

func apciI(ns, nr uint16) []byte {
	b := apdu(100, 6, 1, 0, 20)
	binary.LittleEndian.PutUint16(b[2:4], ns<<1)
	binary.LittleEndian.PutUint16(b[4:6], nr<<1)
	return b
}

func apciS(nr uint16) []byte {
	b := []byte{0x68, 4, 1, 0, 0, 0}
	binary.LittleEndian.PutUint16(b[4:6], nr<<1)
	return b
}

func apciU(fn byte) []byte { return []byte{0x68, 4, fn, 0, 0, 0} }

func apciAlerts(h *iecHarness) []events.Event {
	var out []events.Event
	for _, ev := range h.eventsOf("anomaly") {
		if typ, _ := ev.Attributes["anomaly_type"].(string); strings.HasPrefix(typ, "iec104_") {
			out = append(out, ev)
		}
	}
	return out
}

func TestIECAPCIAlertsObservational(t *testing.T) {
	for _, mode := range []string{"learn", "enforce"} {
		t.Run(mode, func(t *testing.T) {
			h := newAPCIHarness(t, mode)
			emit := h.e.iec.emit
			h.e.iec.emit = func(evs []events.Event) {
				if !h.e.iec.mu.TryLock() {
					t.Fatal("event consumer called under the session lock")
				}
				h.e.iec.mu.Unlock()
				emit(evs)
			}
			h.handshake()
			for _, payload := range [][]byte{
				apciI(0, 0), // before STARTDT con
				startdtCon,
				apciI(2, 0), // gap
				apciI(2, 0), // backwards
				apciS(1),    // peer has never sent an I-frame
				apciU(0x23),
				apciI(3, 0), // after STOPDT con
				apciU(0x43),
			} {
				if _, d := h.send(true, payload); d.Action != capture.Accept {
					t.Fatalf("observation changed decision: %+v", d)
				}
			}
			h.clock = h.clock.Add(anomaly.IEC104T1)
			h.e.iec.expire() // no packets required
			got := apciAlerts(h)
			want := []string{
				anomaly.IEC104DataWhileStopped, anomaly.IEC104SendSequence,
				anomaly.IEC104SendSequence, anomaly.IEC104AckSequence,
				anomaly.IEC104DataWhileStopped, anomaly.IEC104TestTimeout,
			}
			if len(got) != len(want) {
				t.Fatalf("alerts: %+v", got)
			}
			sid := got[0].Attributes["session_id"]
			for i, ev := range got {
				if ev.Proto != "ids" || ev.Attributes["anomaly_type"] != want[i] ||
					ev.Attributes["session_id"] != sid || sid == "" || ev.Attributes["direction"] != "request" {
					t.Fatalf("alert %d: %+v", i, ev)
				}
			}
			if h.e.IEC104Enforcement().Healthy != true || len(h.outcomes()) != 0 {
				t.Fatal("anomalies changed health or session state")
			}
		})
	}
}

func TestIECAPCIOrderedDeduplicatedFrames(t *testing.T) {
	for _, mode := range []string{"learn", "enforce"} {
		t.Run(mode, func(t *testing.T) {
			h := newAPCIHarness(t, mode)
			h.handshake()
			h.send(true, startdtAct)
			h.send(false, startdtCon)
			payload := append(apciI(0, 0), apciI(1, 0)...)
			seq := h.cSeq
			// Tail first, a duplicate tail, then head: a single contiguous
			// delivery containing two APDUs, not three packet observations.
			for _, part := range []struct{ lo, hi int }{{9, len(payload)}, {9, len(payload)}, {0, 9}, {0, len(payload)}} {
				pkt := h.pkt(true, capture.TCPFlagACK, seq+uint32(part.lo), h.sSeq, payload[part.lo:part.hi])
				h.e.handlePacket(pkt)
			}
			h.cSeq += uint32(len(payload))
			h.send(false, apciS(2))
			// A delayed retransmission below the TCP acknowledged floor
			// is not fresh APCI input either.
			h.e.handlePacket(h.pkt(true, capture.TCPFlagACK, seq, h.sSeq, payload))
			// Multiple objects still advance N(S) only once.
			monitor := apdu(3, 3, 1, 1, 2)
			monitor[7] = 2
			monitor = append(monitor, 2, 0, 0, 2)
			monitor[1] += 4
			binary.LittleEndian.PutUint16(monitor[4:6], 4) // ACK client N(S) 0 and 1
			h.send(false, monitor)
			monitor = apdu(3, 3, 1, 1, 2)
			binary.LittleEndian.PutUint16(monitor[2:4], 2)
			binary.LittleEndian.PutUint16(monitor[4:6], 4)
			h.send(false, monitor)
			if got := apciAlerts(h); len(got) != 0 {
				t.Fatalf("ordered/deduplicated traffic: %+v", got)
			}
		})
	}
}

func TestIECAPCIMalformedControlsDoNotAdvanceState(t *testing.T) {
	h := newAPCIHarness(t, "learn")
	h.handshake()
	for _, b := range [][]byte{startdtCon, apciS(1), apciU(0x43)} {
		b = append([]byte(nil), b...)
		b[1]++
		b = append(b, 0) // complete framed APDU, but invalid S/U length
		h.send(true, b)
	}
	h.clock = h.clock.Add(2 * anomaly.IEC104T1)
	h.e.iec.expire()
	if got := apciAlerts(h); len(got) != 0 {
		t.Fatalf("malformed APCI advanced analyzer: %+v", got)
	}
	h.send(true, apciI(0, 0))
	got := apciAlerts(h)
	if len(got) != 1 || got[0].Attributes["anomaly_type"] != anomaly.IEC104DataWhileStopped {
		t.Fatalf("malformed STARTDT con activated data transfer: %+v", got)
	}
}

func TestIECAPCIStateEndsWithObservation(t *testing.T) {
	for _, end := range []string{"close", "abort", "delete", "policy", "parse", "reconfigure"} {
		t.Run(end, func(t *testing.T) {
			h := newAPCIHarness(t, "learn")
			h.handshake()
			h.send(true, apciU(0x43))
			old := h.e.iec
			old.mu.Lock()
			client, _ := addrPort(h.client, h.cport)
			server, _ := addrPort(h.server, iec104Port)
			s, _ := old.lookupLocked(client, server)
			if s.apci == nil {
				t.Fatal("analyzer not attached")
			}
			switch end {
			case "close":
				old.closeLocked(s, h.clock)
			case "abort":
				old.abortLocked(s, abortPolicy, "", nil, h.clock)
			case "delete":
				old.deleteLocked(iecKey{client: s.client, server: s.server}, s)
			case "parse":
				old.stopParseLocked(s)
			}
			old.mu.Unlock()
			switch end {
			case "policy":
				h.policy.matched = false
				h.e.LoadRules(iecSnapshot("learn"))
			case "reconfigure":
				fresh := newAPCIHarness(t, "learn")
				h.e.Reconfigure(fresh.e)
				if len(h.e.iec.sessions) != 0 {
					t.Fatal("reconfigure retained old sessions")
				}
			}
			if end != "reconfigure" && s.apci != nil {
				t.Fatal("observation ended without freeing analyzer")
			}
			h.clock = h.clock.Add(2 * anomaly.IEC104T1)
			h.e.iec.expire()
			if got := apciAlerts(h); len(got) != 0 {
				t.Fatalf("ended timer emitted: %+v", got)
			}
		})
	}
}

func TestIECAPCIReconnectFreshState(t *testing.T) {
	h := newAPCIHarness(t, "learn")
	h.handshake()
	h.send(false, startdtCon)
	h.send(true, apciI(0, 0))
	client, _ := addrPort(h.client, h.cport)
	server, _ := addrPort(h.server, iec104Port)
	h.e.iec.mu.Lock()
	oldID := h.e.iec.sessions[iecKey{client: client, server: server}].id
	h.e.iec.mu.Unlock()
	h.e.handlePacket(h.pkt(true, capture.TCPFlagRST, h.cSeq, h.sSeq, nil))
	h.clientISN, h.serverISN = 100, 200
	h.cSeq, h.sSeq = 101, 201
	for _, p := range []capture.Packet{
		h.pkt(true, capture.TCPFlagSYN, 100, 0, nil),
		h.pkt(false, capture.TCPFlagSYN|capture.TCPFlagACK, 200, 101, nil),
		h.pkt(true, capture.TCPFlagACK, 101, 201, nil),
	} {
		h.e.handlePacket(p)
	}
	h.send(true, apciI(0, 0))
	got := apciAlerts(h)
	if len(got) != 1 || got[0].Attributes["anomaly_type"] != anomaly.IEC104DataWhileStopped ||
		got[0].Attributes["session_id"] == oldID {
		t.Fatalf("reconnect inherited APCI state: %+v", got)
	}
}

// The fixtures are classic little-endian Ethernet PCAPs. Decode every TCP
// packet through the live engine, preserving timestamps, handshakes and FINs.
func TestIECAPCICleanCaptures(t *testing.T) {
	for _, name := range []string{"session-management", "startup-gi-monitor"} {
		for _, mode := range []string{"learn", "enforce"} {
			t.Run(name+"/"+mode, func(t *testing.T) {
				h := newAPCIHarness(t, mode)
				data, err := os.ReadFile(filepath.Join("../../../test/iec104/testdata", name+".pcap"))
				if err != nil {
					t.Fatal(err)
				}
				if len(data) < 24 || binary.LittleEndian.Uint32(data) != 0xa1b2c3d4 ||
					binary.LittleEndian.Uint32(data[20:24]) != 1 {
					t.Fatal("expected little-endian Ethernet PCAP")
				}
				packets, payloads := 0, 0
				for pos := 24; pos < len(data); {
					if pos+16 > len(data) {
						t.Fatal("short record")
					}
					hdr := data[pos : pos+16]
					size := int(binary.LittleEndian.Uint32(hdr[8:12]))
					pos += 16
					if size < 14 || size > len(data)-pos {
						t.Fatal("invalid Ethernet record")
					}
					frame := data[pos : pos+size]
					pos += size
					if binary.BigEndian.Uint16(frame[12:14]) != 0x0800 {
						continue
					}
					p := capture.DecodeIPPacket(frame[14:])
					markHandshake(&p) // as nft queues the capture's handshake
					if p.Transport != "tcp" || !isIECPort(p) {
						continue
					}
					h.clock = time.Unix(int64(binary.LittleEndian.Uint32(hdr)), int64(binary.LittleEndian.Uint32(hdr[4:8]))*1000)
					p.Timestamp, p.Token = h.clock, h.token()
					h.e.iec.expire()
					if d := h.e.handlePacket(p); d.Action != capture.Accept {
						t.Fatalf("packet %d: %+v", packets, d)
					}
					packets++
					if len(p.Payload) > 0 {
						payloads++
						// Real TCP duplicate bytes must never be analyzed twice.
						p.Token = h.token()
						h.e.handlePacket(p)
					}
				}
				h.clock = h.clock.Add(2 * anomaly.IEC104T1)
				h.e.iec.expire()
				decoded := 0
				for _, ev := range h.e.Events().List(0) {
					if ev.Proto == iecProtocol && ev.Attributes["apdu_id"] != nil {
						decoded++
					}
				}
				if packets < 20 || payloads < 10 || decoded < 10 {
					t.Fatalf("vacuous replay: packets=%d payloads=%d", packets, payloads)
				}
				if got := h.eventsOf("anomaly"); len(got) != 0 {
					t.Fatalf("clean capture produced alerts: %+v", got)
				}
				t.Logf("replayed %d packets, %d payloads (also duplicated), zero anomalies", packets, payloads)
			})
		}
	}
}
