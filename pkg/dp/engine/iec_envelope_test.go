// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

package engine

import (
	"net"
	"net/netip"
	"strings"
	"testing"

	"github.com/tonylturner/containd/pkg/dp/capture"
	"github.com/tonylturner/containd/pkg/dp/enforce"
	"github.com/tonylturner/containd/pkg/dp/rules"
)

func TestIECTableNonIPv4UsesRegistryPort(t *testing.T) {
	tab := newIECTable("enforce", &zoneCache{})
	tab.setPolicy(&rules.Snapshot{Firewall: []rules.Entry{{
		ID: "iec", Sources: []string{"2001:db8::10/128"}, Destinations: []string{"2001:db8::20/128"},
		Protocols: []rules.Protocol{{Name: "tcp", Port: "2404"}},
		ICS:       rules.ICSPredicate{Protocol: "iec104", Mode: "enforce"},
	}}})
	pkt := capture.Packet{SrcIP: net.ParseIP("2001:db8::10"), DstIP: net.ParseIP("2001:db8::20"),
		SrcPort: 40000, DstPort: 2404, Proto: 6}
	for _, reverse := range []bool{false, true} {
		if reverse {
			pkt.SrcIP, pkt.DstIP = pkt.DstIP, pkt.SrcIP
			pkt.SrcPort, pkt.DstPort = pkt.DstPort, pkt.SrcPort
		}
		result, matched := tab.nonIPv4Locked(wireServiceState(pkt))
		if !matched || result.decision.Action != capture.Drop || result.decision.Reason != reasonIECInvalid {
			t.Fatalf("reverse=%v matched=%v result=%+v", reverse, matched, result)
		}
	}
}

// TestIECEnvelopeAgreesWithNftSteering: for the same snapshot, the engine
// treats a session as inside an IEC104 envelope exactly when the nft
// compiler steers that rule's traffic to the queue.
func TestIECEnvelopeAgreesWithNftSteering(t *testing.T) {
	comp := enforce.NewCompiler()
	comp.QueueID = 101
	client := netip.MustParseAddrPort("10.60.60.10:40000")
	server := netip.MustParseAddrPort("10.30.30.30:2404")
	cases := []struct {
		name  string
		proto []rules.Protocol
	}{
		{"no protocols", nil},
		{"tcp/2404", []rules.Protocol{{Name: "tcp", Port: "2404"}}},
		{"tcp range", []rules.Protocol{{Name: "tcp", Port: "2400-2410"}}},
		{"tcp any port", []rules.Protocol{{Name: "tcp"}}},
		{"any proto 2404", []rules.Protocol{{Port: "2404"}}},
		{"tcp/502", []rules.Protocol{{Name: "tcp", Port: "502"}}},
		{"udp/2404", []rules.Protocol{{Name: "udp", Port: "2404"}}},
		{"udp then tcp", []rules.Protocol{{Name: "udp", Port: "2404"}, {Name: "tcp", Port: "2404"}}},
	}
	// Known disagreement: nft lower-cases protocol names, the evaluator
	// does not, and validation accepts "TCP". The engine fails closed on
	// such envelope-marked packets (TestIECEnvelopeMarkWithoutEnvelopeDrops).
	for _, c := range cases {
		snap := &rules.Snapshot{Firewall: []rules.Entry{{
			ID: "iec", Sources: []string{"10.60.60.0/24"}, Destinations: []string{"10.30.30.30/32"},
			Protocols: c.proto, Action: rules.ActionAllow,
			ICS: rules.ICSPredicate{Protocol: "iec104", Mode: "enforce"},
		}}}
		tab := newIECTable("learn", &zoneCache{})
		tab.setPolicy(snap)
		matched, mode := tab.envelopeLocked(tab.sessionCtx(client, server))
		if steers := comp.SteersIEC104(snap); steers != matched {
			t.Fatalf("%s: nft steers=%v, engine envelope=%v", c.name, steers, matched)
		}
		if matched && mode != "enforce" {
			t.Fatalf("%s: envelope mode %q", c.name, mode)
		}
	}
}

func TestIECEnvelopeMarkWithoutEnvelopeDrops(t *testing.T) {
	h := newIECHarness(t, "enforce")
	h.policy.matched = false
	p := h.pkt(true, capture.TCPFlagSYN, 1, 0, nil)
	if d := h.e.handlePacket(p); d.Action != capture.Accept {
		t.Fatalf("unmarked SYN outside the envelope = %+v, want the flow path", d)
	}
	p.HasMark, p.Mark = true, enforce.EnvelopeMark
	if d := h.e.handlePacket(p); d.Action != capture.Drop {
		t.Fatalf("envelope-marked SYN without an engine envelope = %+v, want Drop", d)
	}
	if st := h.e.IEC104Enforcement(); st.Healthy || !strings.Contains(st.Reason, "disagree") {
		t.Fatalf("health = %+v", st)
	}
	h.e.LoadRules(iecSnapshot("enforce"))
	if st := h.e.IEC104Enforcement(); !st.Healthy {
		t.Fatalf("health after a new policy = %+v", st)
	}
}
