// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

package engine

import (
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/tonylturner/containd/pkg/dp/capture"
	"github.com/tonylturner/containd/pkg/dp/dpi"
	"github.com/tonylturner/containd/pkg/dp/flow"
	"github.com/tonylturner/containd/pkg/dp/stats"
	"github.com/tonylturner/containd/pkg/dp/verdict"
)

func assertAccounting(t *testing.T, e *Engine, proto string, packets, bytes, events, reads, writes, alerts int64) {
	t.Helper()
	var got stats.ProtoStats
	var totalPackets, totalBytes int64
	for _, ps := range e.ProtoStats() {
		totalPackets += ps.PacketCount
		totalBytes += ps.ByteCount
		if ps.Protocol == proto {
			got = ps
		}
	}
	if got.Protocol != proto || got.PacketCount != packets || got.ByteCount != bytes ||
		got.EventCount != events || got.ReadCount != reads || got.WriteCount != writes || got.AlertCount != alerts ||
		totalPackets != packets || totalBytes != bytes {
		t.Fatalf("stats = %+v (total %d packets/%d bytes), want %s: packets=%d bytes=%d events=%d reads=%d writes=%d alerts=%d",
			e.ProtoStats(), totalPackets, totalBytes, proto, packets, bytes, events, reads, writes, alerts)
	}
	var flowPackets, flowBytes int64
	for _, fs := range e.TopTalkers(0) {
		flowPackets += fs.Packets
		flowBytes += fs.Bytes
		if fs.Protocol != proto {
			t.Fatalf("wrong flow attribution: %+v", fs)
		}
	}
	if flowPackets != packets || flowBytes != bytes {
		t.Fatalf("flow accounting = %d packets/%d bytes, want %d/%d: %+v", flowPackets, flowBytes, packets, bytes, e.TopTalkers(0))
	}
}

func realAccountingIEC(t *testing.T) *iecHarness {
	t.Helper()
	h := newIECHarness(t, "learn")
	h.e.dpiMgr = dpi.NewManager(DefaultDecoders()...)
	h.e.iec.dpi = h.e.dpiMgr
	h.handshake()
	assertAccounting(t, h.e, "iec104", 3, 0, 0, 0, 0, 0)
	return h
}

func TestAccountingIECMultiObjectAndMultiAPDU(t *testing.T) {
	// IEC 104 SQ=0, Type 1: two explicitly addressed single-point objects.
	twoObjects := apdu(1, 20, 1, 1001, 1)
	twoObjects[7] = 2
	twoObjects = append(twoObjects, 0xea, 0x03, 0x00, 0x00) // IOA 1002, SIQ 0
	twoObjects[1] = byte(len(twoObjects) - 2)
	for _, tc := range []struct {
		name    string
		payload []byte
		events  int64
	}{
		{"multi-object ASDU", twoObjects, 2},
		{"multi-APDU packet", append(append([]byte{}, twoObjects...), apdu(3, 3, 1, 1003, 2)...), 3},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := realAccountingIEC(t)
			if _, d := h.send(false, tc.payload); d.Action != capture.Accept {
				t.Fatalf("decision = %+v", d)
			}
			assertAccounting(t, h.e, "iec104", 4, int64(len(tc.payload)), tc.events, tc.events, 0, 0)
			if got := h.eventsOf("response"); int64(len(got)) != tc.events {
				t.Fatalf("decoded object events = %+v", got)
			}
		})
	}
}

func TestAccountingIECSplitAndRetransmit(t *testing.T) {
	payload := apdu(3, 3, 1, 1001, 2)
	for cut := 1; cut < len(payload); cut++ {
		h := realAccountingIEC(t)
		p, _ := h.send(false, payload[:cut])
		// Charge the leading fragment immediately, without any decoder event.
		assertAccounting(t, h.e, "iec104", 4, int64(cut), 0, 0, 0, 0)
		h.send(false, payload[cut:])
		assertAccounting(t, h.e, "iec104", 5, int64(len(payload)), 1, 1, 0, 0)
		h.e.HandlePacket(p) // A received retransmit is another packet, not another object.
		assertAccounting(t, h.e, "iec104", 6, int64(len(payload)+cut), 1, 1, 0, 0)
	}
}

func TestAccountingIECHeldResolutionIsNotAnArrival(t *testing.T) {
	h := newIECHarness(t, "enforce")
	h.e.dpiMgr = dpi.NewManager(DefaultDecoders()...)
	h.e.iec.dpi = h.e.dpiMgr
	h.handshake()
	payload := apdu(3, 3, 1, 1001, 2)
	p, d := h.send(false, payload[:5])
	if d.Action != capture.Hold {
		t.Fatalf("leading fragment = %+v, want Hold", d)
	}
	assertAccounting(t, h.e, "iec104", 4, 5, 0, 0, 0, 0)
	_, d = h.send(false, payload[5:])
	if d.Action != capture.Accept || len(d.Resolved) != 1 || d.Resolved[0].Token != p.Token {
		t.Fatalf("completing fragment = %+v, want Accept and one resolved token", d)
	}
	assertAccounting(t, h.e, "iec104", 5, int64(len(payload)), 1, 1, 0, 0)
}

func TestAccountingIECFailClosedStillCountsPacket(t *testing.T) {
	h := newIECHarness(t, "enforce")
	h.policy.matched = false // nft steering and the runtime envelope disagree.
	p := h.pkt(true, capture.TCPFlagSYN, 100, 0, nil)
	p.HasMark, p.Mark = true, 0x01000000
	if d := h.e.HandlePacket(p); d.Action != capture.Drop || d.Reason != reasonIECFailClose {
		t.Fatalf("steering mismatch = %+v", d)
	}
	assertAccounting(t, h.e, "iec104", 1, 0, 0, 0, 0, 0)
}

func TestAccountingGenericSplitCoalescedAndRetransmit(t *testing.T) {
	e := recordEngine(t)
	e.HandlePacket(recordPacket(100, capture.TCPFlagPSH, "AA"))
	assertAccounting(t, e, "rec", 1, 2, 0, 0, 0, 0)
	e.HandlePacket(recordPacket(102, capture.TCPFlagPSH, "AABBBB"))
	assertAccounting(t, e, "rec", 2, 8, 2, 0, 0, 0)
	e.HandlePacket(recordPacket(100, capture.TCPFlagPSH, "AA"))
	assertAccounting(t, e, "rec", 3, 10, 2, 0, 0, 0)
}

type accountingEndFramer struct{ recordFramer }

func (accountingEndFramer) OnFlowEnd(*flow.State) ([]dpi.Event, error) {
	return []dpi.Event{
		{Proto: "rec", Kind: "write", Attributes: map[string]any{"src": "untrusted", "dst": "event-only"}},
		{Proto: "rec", Kind: "alert"},
	}, nil
}

func TestAccountingFlowEndAddsOnlyEvents(t *testing.T) {
	for _, flag := range []capture.TCPFlags{capture.TCPFlagFIN, capture.TCPFlagRST} {
		e := recordEngine(t)
		e.dpiMgr = dpi.NewManager(accountingEndFramer{})
		// A payload-bearing close produces both packet events and flow-end events.
		e.HandlePacket(recordPacket(100, flag, "AAAA"))
		assertAccounting(t, e, "rec", 1, 4, 3, 0, 1, 1)
	}
}

func TestAccountingNoEventsAndCachedVerdicts(t *testing.T) {
	for _, tc := range []struct {
		name       string
		inspect    bool
		cachedDeny bool
	}{
		{"ACK", true, false},
		{"not inspected", false, false},
		{"cached deny", true, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			e := recordEngine(t)
			e.inspectAll = tc.inspect
			p := recordPacket(100, capture.TCPFlagACK, "")
			if !tc.inspect || tc.cachedDeny {
				p.Payload = []byte("AAAA")
			}
			if tc.cachedDeny {
				st := e.trackFlow(p, p.Timestamp)
				e.verdictCache.Put(st.Key.Hash(), verdict.Verdict{Action: verdict.BlockFlowTemp, TTL: time.Minute})
			}
			e.HandlePacket(p)
			e.HandlePacket(p) // Also covers the cached allow return for non-inspected traffic.
			assertAccounting(t, e, "rec", 2, int64(2*len(p.Payload)), 0, 0, 0, 0)
		})
	}
}

func TestAccountingIECProbeFallsThroughOnce(t *testing.T) {
	e := recordEngine(t)
	p := recordPacket(100, capture.TCPFlagACK, "unparsed")
	p.DstPort = iec104Port
	e.HandlePacket(p)
	assertAccounting(t, e, "tcp", 1, 8, 0, 0, 0, 0)
}

func TestAccountingProtocolAttribution(t *testing.T) {
	e, err := New(Config{DPIEnabled: true})
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name      string
		ipProto   uint8
		port      uint16
		transport string
		want      string
	}{
		{"HTTP without events", 6, 80, "tcp", "http"},
		{"DNS without events", 17, 53, "udp", "dns"},
		{"unsupported port", 6, 102, "tcp", "tcp"},
		{"unsupported TCP port", 6, 4840, "tcp", "tcp"},
		{"unsupported UDP port", 17, 47808, "udp", "udp"},
		{"unclassified UDP port", 17, 18245, "udp", "udp"},
		{"unknown service", 6, 9999, "tcp", "tcp"},
		{"reverse Modbus", 6, 502, "tcp", "modbus"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			key := flow.Key{Proto: tc.ipProto, SrcPort: 40000, DstPort: tc.port}
			if tc.name == "reverse Modbus" {
				key.SrcPort, key.DstPort = key.DstPort, key.SrcPort
			}
			if got := e.packetStatsProtocol(flow.NewState(key, time.Now()), tc.transport); got != tc.want {
				t.Fatalf("attribution = %s, want %s", got, tc.want)
			}
		})
	}
}

func TestAccountingModbusReadsAndWritesRemainSemantic(t *testing.T) {
	e := newModbusInspectEngine(t)
	payload := append(modbusADU(1, 3, 0, 2), modbusADU(2, 6, 1, 7)...)
	p := clientSegment("", 100, capture.TCPFlagPSH|capture.TCPFlagACK, payload)
	e.HandlePacket(p)
	assertAccounting(t, e, "modbus", 1, int64(len(payload)), 2, 1, 1, 0)
}

func TestAccountingInvalidPacketHasNoTrustedFlow(t *testing.T) {
	e := recordEngine(t)
	p := recordPacket(100, capture.TCPFlagPSH, "AAAA")
	p.Invalid = capture.InvalidFragment
	e.HandlePacket(p)
	got := e.ProtoStats()
	if len(got) != 1 || got[0].Protocol != "tcp" || got[0].PacketCount != 1 || got[0].ByteCount != 4 || got[0].EventCount != 0 {
		t.Fatalf("invalid packet accounting = %+v", got)
	}
	if top := e.TopTalkers(0); len(top) != 0 {
		t.Fatalf("invalid tuple produced flow counters: %+v", top)
	}
}

func TestAccountingEventsWithoutPacketOrStore(t *testing.T) {
	e := &Engine{stats: stats.New()}
	e.RecordDPIEvents(nil, nil, []dpi.Event{{Proto: "iec104", Kind: "response"}})
	got := e.ProtoStats()
	if len(got) != 1 || got[0].EventCount != 1 || got[0].PacketCount != 0 || got[0].ByteCount != 0 {
		t.Fatalf("event-only accounting = %+v", got)
	}
}

type accountingCountingFramer struct {
	recordFramer
	supportCalls atomic.Int64
}

func (d *accountingCountingFramer) Supports(state *flow.State) bool {
	d.supportCalls.Add(1)
	return d.recordFramer.Supports(state)
}

func TestAccountingResolvesEachFlowOnce(t *testing.T) {
	e := recordEngine(t)
	dec := &accountingCountingFramer{}
	e.dpiMgr = dpi.NewManager(dec)
	pkt := recordPacket(100, capture.TCPFlagACK, "")
	state := e.trackFlow(pkt, pkt.Timestamp)
	var wg sync.WaitGroup
	for range 8 {
		wg.Go(func() {
			for range 100 {
				e.recordPacketStats(pkt, state)
			}
		})
	}
	wg.Wait()
	if got := dec.supportCalls.Load(); got != 1 {
		t.Fatalf("Supports called %d times for one flow, want 1", got)
	}
	assertAccounting(t, e, "rec", 800, 0, 0, 0, 0, 0)
	if allocs := testing.AllocsPerRun(100, func() { e.recordPacketStats(pkt, state) }); allocs != 0 {
		t.Fatalf("steady-state accounting allocated %g times per packet", allocs)
	}
}

func TestAccountingLaterEventsDoNotRelabelTransport(t *testing.T) {
	e := recordEngine(t)
	pkt := recordPacket(100, capture.TCPFlagACK, "")
	state := e.trackFlow(pkt, pkt.Timestamp)
	e.recordPacketStats(pkt, state)
	// Transport attribution is a flow-service label, not payload detection.
	// A new event protocol must neither move nor duplicate captured traffic.
	e.RecordDPIEvents(state, nil, []dpi.Event{{Proto: "later-service", Kind: "detect"}})
	e.recordPacketStats(pkt, state)
	assertAccounting(t, e, "rec", 2, 0, 0, 0, 0, 0)
}

func TestAccountingDecoderReconfigureResolvesFreshFlow(t *testing.T) {
	e, err := New(Config{DPIEnabled: true})
	if err != nil {
		t.Fatal(err)
	}
	pkt := clientSegment("", 100, capture.TCPFlagACK, nil)
	oldState := e.trackFlow(pkt, pkt.Timestamp)
	e.recordPacketStats(pkt, oldState)
	assertAccounting(t, e, "modbus", 1, 0, 0, 0, 0, 0)
	fresh, err := New(Config{DPIEnabled: true, Events: e.Events(), DPIICSProtocols: map[string]bool{"modbus": false}})
	if err != nil {
		t.Fatal(err)
	}
	e.Reconfigure(fresh)
	state := e.trackFlow(pkt, pkt.Timestamp)
	if state == oldState {
		t.Fatal("reconfigure reused a flow carrying an old decoder-set label")
	}
	e.recordPacketStats(pkt, state)
	assertAccounting(t, e, "tcp", 1, 0, 0, 0, 0, 0)
}
