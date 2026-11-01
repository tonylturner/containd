// SPDX-License-Identifier: Apache-2.0

package engine

import (
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/tonylturner/containd/pkg/dp/capture"
	"github.com/tonylturner/containd/pkg/dp/enforce"
	"github.com/tonylturner/containd/pkg/dp/flow"
	"github.com/tonylturner/containd/pkg/dp/markabi"
	"github.com/tonylturner/containd/pkg/dp/rules"
)

func TestQueuePolicyContextOriginalReplyAndMissingEvidence(t *testing.T) {
	public := netip.MustParseAddrPort("203.0.113.2:1502")
	snap := &rules.Snapshot{ZoneIfaces: map[string][]string{"client": {"eth1"}, "backend": {"eth0"}},
		LocalIPv4ByDevice: map[string][]netip.Addr{"eth1": {public.Addr()}},
		Gate:              rules.GateSelection{Zones: []rules.GateZone{{Name: "backend", Index: 7}}}}
	for _, reply := range []bool{false, true} {
		pkt := connSegment(reply, 41000, 502, 100, ackPsh, nil)
		pkt.Queue.Conntrack.Mark = markabi.OwnedForwardCtBit
		pkt.Queue.Conntrack.Original.Destination = public
		p := inlinePolicy(pkt, snap)
		ctx := p.Context
		if p.Reply != reply || ctx.IngressDevice != "eth1" || ctx.EgressDevice != "eth0" ||
			ctx.SrcZone != "client" || ctx.DstZone != "backend" || ctx.Port != "502" ||
			!ctx.SrcIP.Equal(net.ParseIP(testClient)) || !ctx.DstIP.Equal(net.ParseIP(testServer)) {
			t.Fatalf("reply=%t context=%+v", reply, ctx)
		}
		forward := rules.ForwardMatch{Enabled: true, IngressDevices: []string{"eth1"}, Protocol: "tcp",
			ListenPort: 1502, Backend: pkt.Queue.Conntrack.Reply.Source}
		if !forward.Matches(ctx, snap.LocalIPv4ByDevice) {
			t.Fatalf("reply=%t verified via did not match", reply)
		}
		pkt.Queue.Conntrack.HasMark = false
		if got := inlinePolicy(pkt, snap); got.Context.Conntrack != nil || forward.Matches(got.Context, snap.LocalIPv4ByDevice) {
			t.Fatal("missing mark became verified via")
		}
		pkt.Queue.Conntrack.HasMark = true
		pkt.Queue.Conntrack.Original.Source = netip.AddrPort{}
		if got := inlinePolicy(pkt, snap); got.Context.SrcIP != nil {
			t.Fatal("invented original source from packet header")
		}
		pkt.Queue.Conntrack = nil
		pkt.Queue.IngressDevice, pkt.Queue.EgressDevice = "", ""
		got := inlinePolicy(pkt, snap)
		if got.Context.SrcZone != "" || got.Context.DstZone != "" || got.Context.Conntrack != nil ||
			!got.Context.SrcIP.Equal(pkt.SrcIP) || got.Reply {
			t.Fatal("missing CT/interfaces did not retain only trustworthy headers")
		}
	}
	pkt := connSegment(false, 41000, 502, 100, ackPsh, nil)
	pkt.Queue.EgressDevice = ""
	pkt.Queue.Conntrack.Mark = enforce.GateCtMark | 7<<enforce.GateZoneCtShift
	p := inlinePolicy(pkt, snap)
	if p.Context.DstZone != "backend" || p.Context.EgressDevice != "" {
		t.Fatal("gate did not resolve its verified zone without inventing a device")
	}
	state := flow.NewState(p.Service, time.Now())
	state.InlinePolicy.Store(p)
	snap.Gate.Zones = nil
	if statePolicyContext(snap, state, &zoneCache{}).DstZone != "" {
		t.Fatal("retained retired gate zone")
	}
}

func TestContinuationS4Routing(t *testing.T) {
	scope := clientToServer("inspect", "502", rules.ActionAllow, rules.ICSPredicate{Protocol: "modbus", FunctionCode: []uint8{99}, Mode: "enforce"})
	plain := func(action rules.Action) rules.Entry {
		return rules.Entry{ID: "plain", Action: action, Protocols: []rules.Protocol{{Name: "tcp", Port: "502"}}}
	}
	icsDeny := scope
	icsDeny.ID, icsDeny.Action, icsDeny.ICS.FunctionCode = "ics-deny", rules.ActionDeny, []uint8{3}
	for _, tc := range []struct {
		name     string
		entries  []rules.Entry
		def      rules.Action
		want     capture.Disposition
		nonAdmit bool
	}{
		{"plain deny", []rules.Entry{plain(rules.ActionDeny), scope}, rules.ActionAllow, capture.Repeat, true},
		{"plain reset", []rules.Entry{plain(rules.ActionReset), scope}, rules.ActionAllow, capture.Repeat, true},
		{"default deny", []rules.Entry{scope}, rules.ActionDeny, capture.Repeat, true},
		{"earlier plain allow", []rules.Entry{plain(rules.ActionAllow), icsDeny}, rules.ActionDeny, capture.Repeat, false},
		{"ICS deny", []rules.Entry{icsDeny, plain(rules.ActionAllow)}, rules.ActionAllow, capture.Drop, false},
		{"default allow", []rules.Entry{scope}, rules.ActionAllow, capture.Repeat, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newFCFlow(t, "ok", 502)
			f.e.LoadRules(rules.Snapshot{Default: tc.def, Firewall: tc.entries})
			f.syn()
			d := f.decide(0, ackPsh, modbusADU(1, 3, 0, 1))
			if d.Action != tc.want || d.Action == capture.Repeat && (d.Mark&markabi.NonAdmitMark != 0) != tc.nonAdmit {
				t.Fatalf("decision=%+v, want %v NonAdmit=%t", d, tc.want, tc.nonAdmit)
			}
			if tc.nonAdmit && f.e.verdictCache.Len() != 0 {
				t.Fatal("cached ordinary kernel denial in userspace")
			}
		})
	}
}

func TestContinuationCapturedReplyRouting(t *testing.T) {
	scope := clientToServer("inspect", "20000", rules.ActionAllow,
		rules.ICSPredicate{Protocol: "dnp3", FunctionCode: []uint8{99}, Mode: "enforce"})
	plain := clientToServer("plain", "20000", rules.ActionDeny, rules.ICSPredicate{})
	icsDeny := scope
	icsDeny.ID, icsDeny.Action, icsDeny.ICS.FunctionCode = "response-denied", rules.ActionDeny, []uint8{130}
	icsDeny.ICS.Direction = "response"
	for _, tc := range []struct {
		name     string
		entries  []rules.Entry
		want     capture.Disposition
		nonAdmit bool
	}{
		{"unmatched default suppressed", []rules.Entry{scope}, capture.Repeat, false},
		{"explicit plain deny", []rules.Entry{plain, scope}, capture.Repeat, true},
		{"explicit ICS deny", []rules.Entry{icsDeny, scope}, capture.Drop, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newModeFlow(t, "enforce", dnp3Port)
			f.e.LoadRules(rules.Snapshot{Default: rules.ActionDeny, Firewall: tc.entries})
			f.syn()
			f.synAck()
			pkt := connSegment(true, f.client, f.port, resyncServerISN, ackPsh, dnp3Unsolicited)
			pkt.Token = capture.NewToken(1, firstCommandTokens.Add(1))
			d := f.e.HandlePacket(pkt)
			if protoEvents(f.e, "dnp3") != 1 {
				t.Fatalf("captured reply messages: decision=%+v events=%+v", d, f.e.Events().List(0))
			}
			if d.Action != tc.want || d.Action == capture.Repeat && (d.Mark&markabi.NonAdmitMark != 0) != tc.nonAdmit {
				t.Fatalf("captured reply=%+v, want %v NonAdmit=%t", d, tc.want, tc.nonAdmit)
			}
		})
	}
}

func TestMissingEnforcingContextVeto(t *testing.T) {
	f := newFCFlow(t, "ok", 502)
	snap := firstCommandPolicy()
	snap.ZoneIfaces = map[string][]string{"client": {"eth1"}, "backend": {"eth0"}}
	for i := range snap.Firewall {
		snap.Firewall[i].SourceZones = []string{"client"}
	}
	f.e.LoadRules(snap)
	pkt := connSegment(false, 41000, 502, 100, ackPsh, nil)
	pkt.Token = capture.NewToken(1, firstCommandTokens.Add(1))
	pkt.Mark, pkt.HasMark = markabi.EnforceScopeMark, true
	pkt.Queue = &capture.QueueMetadata{}
	if d := f.e.HandlePacket(pkt); d.Action != capture.Drop || d.Reason != "missing_enforce_scope" {
		t.Fatalf("missing context=%+v", d)
	}
	pkt.Invalid = capture.InvalidTruncated
	if d := f.e.HandlePacket(pkt); d.Action != capture.Drop {
		t.Fatalf("invalid enforcing packet=%+v", d)
	}
}
