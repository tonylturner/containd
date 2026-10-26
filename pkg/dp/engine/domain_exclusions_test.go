// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 containd Authors

package engine

import (
	"encoding/binary"
	"fmt"
	"net"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/tonylturner/containd/pkg/dp/capture"
	"github.com/tonylturner/containd/pkg/dp/dpi"
	"github.com/tonylturner/containd/pkg/dp/flow"
)

type domainProbe struct{ calls int }

func (*domainProbe) Supports(*flow.State) bool { return true }
func (p *domainProbe) OnPacket(_ *flow.State, pkt *dpi.ParsedPacket) ([]dpi.Event, error) {
	if len(pkt.Payload) > 0 {
		p.calls++
	}
	return nil, nil
}
func (*domainProbe) OnFlowEnd(*flow.State) ([]dpi.Event, error) { return nil, nil }

func domainTestEngine(t *testing.T) (*Engine, *domainProbe) {
	t.Helper()
	e, err := New(Config{
		InspectAll: true, DPIEnabled: true,
		DPIExclusions: []DPIExclusion{{Type: "domain", Value: "*.example.com"}},
		DPIProtocols:  map[string]bool{"dns": false, "tls": false},
	})
	if err != nil {
		t.Fatal(err)
	}
	probe := &domainProbe{}
	e.dpiMgr = dpi.NewManager(probe)
	return e, probe
}

func domainDNSName(name string) []byte {
	var p []byte
	for _, label := range strings.Split(name, ".") {
		p = append(p, byte(len(label)))
		p = append(p, label...)
	}
	return append(p, 0)
}

func domainDNSResponse(name string, ttl uint32) []byte {
	p := []byte{0, 1, 0x81, 0x80, 0, 1, 0, 1, 0, 0, 0, 0}
	p = append(p, domainDNSName(name)...)
	p = append(p, 0, 1, 0, 1, 0xc0, 0x0c, 0, 1, 0, 1)
	p = binary.BigEndian.AppendUint32(p, ttl)
	return append(p, 0, 4, 10, 0, 0, 2)
}

func domainHello(name string) []byte {
	body := append([]byte{3, 3}, make([]byte, 32)...)
	body = append(body, 0, 0, 2, 0x13, 1, 1, 0)
	var ext []byte
	if name != "" {
		sni := binary.BigEndian.AppendUint16(nil, uint16(len(name)+3))
		sni = append(sni, 0)
		sni = binary.BigEndian.AppendUint16(sni, uint16(len(name)))
		sni = append(sni, name...)
		ext = append(ext, 0, 0)
		ext = binary.BigEndian.AppendUint16(ext, uint16(len(sni)))
		ext = append(ext, sni...)
	}
	body = binary.BigEndian.AppendUint16(body, uint16(len(ext)))
	body = append(body, ext...)
	hs := []byte{1, byte(len(body) >> 16), byte(len(body) >> 8), byte(len(body))}
	hs = append(hs, body...)
	record := binary.BigEndian.AppendUint16([]byte{0x16, 3, 1}, uint16(len(hs)))
	return append(record, hs...)
}

func domainClientPacket(port uint16, payload []byte) capture.Packet {
	return capture.Packet{
		SrcIP: net.ParseIP("10.0.0.1"), DstIP: net.ParseIP("10.0.0.2"),
		SrcPort: port, DstPort: 443, Proto: 6, Transport: "tcp", Payload: payload,
	}
}

func observeTestDNS(e *Engine, ttl uint32) {
	e.HandlePacket(capture.Packet{
		SrcIP: net.ParseIP("10.0.0.53"), DstIP: net.ParseIP("10.0.0.1"),
		SrcPort: 53, DstPort: 53000, Proto: 17, Transport: "udp",
		Payload: domainDNSResponse("shared.example.com", ttl),
	})
}

func domainCounter(e *Engine, reason string) int64 {
	for _, stat := range e.ProtoStats() {
		if stat.Protocol == reason {
			return stat.EventCount
		}
	}
	return 0
}

func TestDomainFlowDecisions(t *testing.T) {
	e, probe := domainTestEngine(t)
	observeTestDNS(e, 300)
	baseline := probe.calls
	tests := []struct {
		name    string
		payload []byte
		skip    bool
	}{
		{"matching SNI", domainHello("MATCH.Example.Com."), true},
		{"nonmatching SNI overrides DNS", domainHello("unrelated.test"), false},
		{"wildcard excludes apex", domainHello("example.com"), false},
		{"no SNI uses DNS", domainHello(""), true},
		{"non TLS shared IP uses DNS", []byte("GET / HTTP/1.0\r\n\r\n"), true},
	}
	for i, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			pkt := domainClientPacket(uint16(40000+i), nil)
			e.HandlePacket(pkt) // handshake-only packets cannot decide
			state := e.trackFlow(pkt, time.Now())
			if !e.ShouldInspect(state, &dpi.ParsedPacket{Proto: "tcp", DstPort: 443}) {
				t.Fatal("decided before first client payload")
			}
			before := probe.calls
			pkt.Payload = tc.payload
			e.HandlePacket(pkt)
			if (probe.calls == before) != tc.skip {
				t.Fatalf("decoder calls %d -> %d, skip %v", before, probe.calls, tc.skip)
			}
			// A later matching SNI must not reverse a negative decision, nor
			// may a nonmatching one reverse an excluded flow.
			pkt.Payload = domainHello("later.example.com")
			if tc.skip {
				pkt.Payload = domainHello("unrelated.test")
			}
			e.HandlePacket(pkt)
			if (probe.calls == before) != tc.skip {
				t.Fatal("later payload reversed decision")
			}
			reply := pkt
			reply.SrcIP, reply.DstIP = pkt.DstIP, pkt.SrcIP
			reply.SrcPort, reply.DstPort = pkt.DstPort, pkt.SrcPort
			before = probe.calls
			e.HandlePacket(reply)
			if (probe.calls == before) != tc.skip {
				t.Fatal("reply did not inherit client decision")
			}
		})
	}
	if probe.calls <= baseline || domainCounter(e, "dpi_exclusion_sni") != 1 || domainCounter(e, "dpi_exclusion_dns") != 2 {
		t.Fatalf("unexpected counters: %+v", e.ProtoStats())
	}
}

func TestDomainDecisionTimingAndExpiry(t *testing.T) {
	e, probe := domainTestEngine(t)
	now := time.Unix(1000, 0)
	e.domains.now = func() time.Time { return now }
	old := domainClientPacket(40000, []byte("first"))
	e.HandlePacket(old) // no association yet; inspected permanently
	observeTestDNS(e, 0)
	before := probe.calls
	e.HandlePacket(old)
	if probe.calls != before+1 {
		t.Fatal("a later DNS answer changed an inspected decision")
	}
	fresh := domainClientPacket(40001, []byte("first"))
	e.HandlePacket(fresh)
	if probe.calls != before+1 {
		t.Fatal("DNS association failed to exclude fresh flow")
	}
	now = now.Add(30 * time.Second)
	e.HandlePacket(fresh)
	if probe.calls != before+1 {
		t.Fatal("TTL expiry reversed existing decision")
	}
	fresh.SrcPort++
	e.HandlePacket(fresh)
	if probe.calls != before+2 {
		t.Fatal("expired association excluded new flow")
	}
}

func TestDomainSNIWithoutDNS(t *testing.T) {
	e, probe := domainTestEngine(t)
	pkt := domainClientPacket(40000, domainHello("sni.example.com"))
	pkt.DstPort = 12345 // exclusion SNI parsing is not port-restricted
	e.HandlePacket(pkt)
	if probe.calls != 0 || domainCounter(e, "dpi_exclusion_sni") != 1 {
		t.Fatal("matching SNI without DNS was not excluded")
	}
	pkt.SrcPort++
	pkt.Payload = domainHello("other.test")
	e.HandlePacket(pkt)
	if probe.calls != 1 {
		t.Fatal("nonmatching SNI without DNS was excluded")
	}
	// A new SYN on a reused tuple discards its previous domain decision,
	// including when the engine's directional flow object is reused.
	pkt.SrcPort--
	pkt.Payload = nil
	pkt.TCP = capture.TCPMeta{Valid: true, Flags: capture.TCPFlagSYN}
	e.HandlePacket(pkt)
	pkt.TCP = capture.TCPMeta{}
	pkt.Payload = domainHello("other.test")
	e.HandlePacket(pkt)
	if probe.calls != 2 {
		t.Fatal("tuple reuse retained the previous exclusion")
	}
}

func TestDomainSharedUDPAndObservationBeforeSelection(t *testing.T) {
	e, probe := domainTestEngine(t)
	observeTestDNS(e, 300)
	before := probe.calls
	pkt := domainClientPacket(40000, []byte("datagram"))
	pkt.Proto, pkt.Transport, pkt.DstPort = 17, "udp", 10000
	e.HandlePacket(pkt)
	pkt.SrcPort++
	e.HandlePacket(pkt)
	if probe.calls != before || domainCounter(e, "dpi_exclusion_dns") != 2 {
		t.Fatal("shared-IP UDP flows were not excluded")
	}
	// Pin a DNS flow as excluded, then feed a response on that flow. DNS
	// observation must still run, even though the decoder is never called.
	pkt.SrcPort, pkt.DstPort = 53, 53001
	pkt.Payload = []byte("not a DNS response")
	e.HandlePacket(pkt)
	pkt.Payload = domainDNSResponse("learned.example.com", 300)
	pkt.Payload[len(pkt.Payload)-1] = 3
	e.HandlePacket(pkt)
	if probe.calls != before {
		t.Fatal("excluded DNS flow reached the decoder")
	}
	pkt = domainClientPacket(41000, []byte("first"))
	pkt.DstIP = net.ParseIP("10.0.0.3")
	e.HandlePacket(pkt)
	if probe.calls != before {
		t.Fatal("DNS was not learned before exclusion selection")
	}
}

func TestDomainIECEnvelopeCannotBeExempted(t *testing.T) {
	h := newIECHarness(t, "enforce")
	h.e.dpiExclusions = []DPIExclusion{{Type: "domain", Value: "*.example.com"}}
	h.e.domains = newDomainExclusions(h.e.dpiExclusions)
	ip, _ := netip.AddrFromSlice(h.server)
	h.e.domains.add(ip, "server.example.com", 300)
	h.handshake()
	if _, d := h.send(true, iframe(45, 1)); d.Action != capture.Drop {
		t.Fatalf("domain association bypassed IEC104 denial: %+v", d)
	}
	if domainCounter(h.e, "dpi_exclusion_dns") != 0 {
		t.Fatal("IEC104 was counted as a domain exclusion")
	}
}

func TestDomainCacheBoundsAndTTL(t *testing.T) {
	d := newDomainExclusions([]DPIExclusion{{Type: "domain"}})
	now := time.Unix(1000, 0)
	d.now = func() time.Time { return now }
	d.capacity = 2
	a, b, c := netip.MustParseAddr("10.0.0.1"), netip.MustParseAddr("10.0.0.2"), netip.MustParseAddr("10.0.0.3")
	d.add(a, "a.example", 0)
	d.add(b, "b.example", 999999)
	if d.lookup(a) == "" {
		t.Fatal("minimum TTL not clamped")
	}
	d.add(c, "c.example", 60) // a was touched; b is LRU
	if d.lookup(b) != "" || d.evictions != 1 || len(d.associations) != 2 || len(d.byIP) != 2 {
		t.Fatal("LRU bound failed")
	}
	now = now.Add(30 * time.Second)
	if d.lookup(a) != "" {
		t.Fatal("minimum TTL did not expire")
	}
	d.add(b, "b.example", 999999)
	now = now.Add(time.Hour)
	if d.lookup(b) != "" || len(d.associations) > d.capacity {
		t.Fatal("maximum TTL did not expire")
	}
}

func TestDomainDecisionLifetime(t *testing.T) {
	e, _ := domainTestEngine(t)
	pkt := domainClientPacket(40000, domainHello("match.example.com"))
	e.HandlePacket(pkt)
	live := e.trackFlow(pkt, time.Now())
	// A removed flow and an older incarnation of a reused tuple cannot hold
	// decisions indefinitely, but capacity pressure must not reverse live ones.
	old := flow.NewState(live.Key, time.Now().Add(-time.Minute))
	e.domains.decisions[old] = true
	for range 65537 {
		e.domains.decisions[&flow.State{}] = false
	}
	if !e.domainExcluded(live) {
		t.Fatal("capacity pressure reversed a live decision")
	}
	e.domains.mu.Lock()
	e.pruneDomainDecisionsLocked()
	e.domains.mu.Unlock()
	if len(e.domains.decisions) != 1 || !e.domainExcluded(live) {
		t.Fatal("decisions did not follow tracked flow lifetime")
	}
}

func TestDomainWildcard(t *testing.T) {
	for _, tc := range []struct {
		pattern, name string
		want          bool
	}{
		{"example.com", "EXAMPLE.COM.", true},
		{"*.example.com.", "one.two.EXAMPLE.com", true},
		{"*.example.com", "example.com", false},
		{"*.example.com", "notexample.com", false},
		{"*.example.com", "example.com.evil", false},
		{"example.com", "sub.example.com", false},
	} {
		if got := domainMatches(tc.pattern, tc.name); got != tc.want {
			t.Errorf("%s / %s = %v", tc.pattern, tc.name, got)
		}
	}
}

func TestDomainDisabledIECAndReconfigure(t *testing.T) {
	e, _ := domainTestEngine(t)
	observeTestDNS(e, 300)
	pkt := domainClientPacket(40000, domainHello("match.example.com"))
	e.HandlePacket(pkt)
	st := e.trackFlow(pkt, time.Now())
	st.Key.DstPort = iec104Port
	if e.domainExcluded(st) {
		t.Fatal("domain exemption bypassed IEC104")
	}
	// Reconfiguration replaces both learned associations and pinned decisions.
	fresh, _ := domainTestEngine(t)
	e.Reconfigure(fresh)
	if len(e.domains.associations) != 0 || len(e.domains.decisions) != 0 {
		t.Fatal("reconfiguration retained domain state")
	}
	if d := newDomainExclusions([]DPIExclusion{{Type: "ip", Value: "10.0.0.2"}}); d != nil {
		t.Fatal("domain processing enabled without a domain exclusion")
	}
}

func TestDomainEvictionsObservable(t *testing.T) {
	e, _ := domainTestEngine(t)
	e.domains.capacity = 1
	for i := range 2 {
		p := domainDNSResponse(fmt.Sprintf("host%d.example.com", i), 300)
		p[len(p)-1] = byte(2 + i)
		e.HandlePacket(capture.Packet{
			SrcIP: net.ParseIP("10.0.0.53"), DstIP: net.ParseIP("10.0.0.1"),
			SrcPort: 53, DstPort: 53000, Proto: 17, Transport: "udp", Payload: p,
		})
	}
	if got := domainCounter(e, "dpi_domain_cache_eviction"); got != 1 {
		t.Fatalf("eviction counter = %d", got)
	}
}
