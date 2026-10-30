// SPDX-License-Identifier: Apache-2.0

package engine

import (
	"net/netip"
	"reflect"
	"sync"
	"testing"
	"time"

	"github.com/tonylturner/containd/pkg/dp/capture"
	"github.com/tonylturner/containd/pkg/dp/conntrack"
	"github.com/tonylturner/containd/pkg/dp/dpi"
	"github.com/tonylturner/containd/pkg/dp/enforce"
	"github.com/tonylturner/containd/pkg/dp/events"
	"github.com/tonylturner/containd/pkg/dp/flow"
	"github.com/tonylturner/containd/pkg/dp/ics/cip"
	"github.com/tonylturner/containd/pkg/dp/ics/dnp3"
	"github.com/tonylturner/containd/pkg/dp/ics/iec104"
	"github.com/tonylturner/containd/pkg/dp/ics/modbus"
	"github.com/tonylturner/containd/pkg/dp/identify"
	"github.com/tonylturner/containd/pkg/dp/rules"
	"github.com/tonylturner/containd/pkg/dp/session"
)

func policyNAT() *flow.Connection {
	return &flow.Connection{Key: "nat-policy", Status: "resolved", Evidence: &conntrack.Evidence{
		Original: conntrack.Tuple{Family: 2, Protocol: 6, Source: netip.MustParseAddrPort(testClient + ":41000"), Destination: netip.MustParseAddrPort("203.0.113.1:1502")},
		Reply:    conntrack.Tuple{Family: 2, Protocol: 6, Source: netip.MustParseAddrPort(testServer + ":502"), Destination: netip.MustParseAddrPort("192.0.2.99:52000")},
	}}
}

func natPolicyStates(c *flow.Connection) []*flow.State {
	keys := []flow.Key{
		flow.TupleKey(c.Evidence.Original, flow.DirForward),
		flow.TupleKey(c.Evidence.Reply, flow.DirReverse).Reversed(),
		flow.TupleKey(c.Evidence.Reply, flow.DirReverse),
		flow.TupleKey(c.Evidence.Original, flow.DirForward).Reversed(),
	}
	var states []*flow.State
	for _, key := range keys {
		state := flow.NewState(key, time.Now())
		state.Connection.Store(c)
		states = append(states, state)
	}
	return states
}

func TestNATPolicyBothLegs(t *testing.T) {
	c := policyNAT()
	for _, action := range []rules.Action{rules.ActionAllow, rules.ActionDeny} {
		t.Run(string(action), func(t *testing.T) {
			entry := clientToServer("backend", "502", action, rules.ICSPredicate{Protocol: "modbus", FunctionCode: []uint8{3}, Mode: "enforce"})
			entry.Log = true
			public := entry
			public.ID, public.Destinations = "public", []string{"203.0.113.1/32"}
			public.Protocols = []rules.Protocol{{Name: "tcp", Port: "1502"}}
			public.Action = rules.ActionDeny
			e, _ := newEnforceEngine(t, rules.ActionAllow, public, entry)
			for _, state := range natPolicyStates(c) {
				pkt := &dpi.ParsedPacket{Proto: "tcp", SrcPort: state.Key.SrcPort, DstPort: state.Key.DstPort}
				ev := dpi.Event{Proto: "modbus", Kind: "request", Attributes: map[string]any{"function_code": uint8(3)}}
				v, ctx, denied := e.enforceDPIEvents(state, pkt, []dpi.Event{ev}, false)
				if denied != (action == rules.ActionDeny) {
					t.Fatalf("%s verdict = %+v, denied=%v", state.ID(), v, denied)
				}
				contexts := evalContextsFromDPIEvent(e.CurrentRules(), state, pkt, ev, "", "")
				_, matched := rules.NewEvaluator(e.CurrentRules()).EvaluateMatch(contexts[0])
				if matched == nil || matched.ID != "backend" {
					t.Fatalf("matched public tuple or no rule: %+v", matched)
				}
				if denied && (ctx.SrcIP.String() != testClient || ctx.DstIP.String() != testServer || ctx.Port != "502") {
					t.Fatalf("not pre-SNAT client -> backend: %+v", ctx)
				}
				hit := e.Events().List(1)[0]
				wirePort := state.Key.DstPort
				if state.Key.Dir == flow.DirReverse {
					wirePort = state.Key.SrcPort
				}
				if hit.Kind != "firewall.rule.hit" || hit.SrcIP != state.Key.OpenerIP().String() || hit.DstIP != state.Key.ServerIP().String() || hit.DstPort != wirePort {
					t.Fatalf("rule-hit endpoints left wire space: %+v", hit)
				}
				if !e.ShouldInspect(state, pkt) || e.conformanceScope(state, pkt, "modbus") == nil {
					t.Fatal("backend service not selected for inspection")
				}
				inline := capture.Packet{Token: capture.NewToken(1, firstCommandTokens.Add(1))}
				if e.failClosedRule(inline, state, pkt) == nil {
					t.Fatal("backend fail-closed scope missed")
				}
			}
		})
	}
}

func TestNATDispatchModbusBothLegs(t *testing.T) {
	c := policyNAT()
	e, _ := newEnforceEngine(t, rules.ActionAllow, clientToServer("backend", "502", rules.ActionAllow, rules.ICSPredicate{Protocol: "modbus"}))
	for _, state := range natPolicyStates(c) {
		id := state.ID()
		result := e.DPI().Inspect(state, &dpi.ParsedPacket{Proto: "tcp", SrcPort: state.Key.SrcPort, DstPort: state.Key.DstPort, Payload: modbusADU(1, 3, 10, 2)})
		if result.Err != nil || result.Proto != "modbus" || len(result.Events) != 1 {
			t.Fatalf("%s dispatch = %+v", id, result)
		}
		if result.Events[0].FlowID != id || state.ID() != id {
			t.Fatal("dispatch rewrote wire identity")
		}
	}
}

func TestNATDispatchLateEvidenceKeepsCommittedDecoder(t *testing.T) {
	c := policyNAT()
	state := flow.NewState(flow.TupleKey(c.Evidence.Original, flow.DirForward), time.Now())
	manager := dpi.NewManager(modbus.NewDecoder(), dnp3.NewDecoder())
	pkt := &dpi.ParsedPacket{Proto: "tcp", SrcPort: state.Key.SrcPort, DstPort: state.Key.DstPort, Payload: modbusADU(1, 3, 10, 2)}
	if result := manager.Inspect(state, pkt); result.Framed || len(result.Events) != 0 {
		t.Fatal("unverified public:1502 selected a legacy decoder")
	}
	state.Connection.Store(c)
	if result := manager.Inspect(state, pkt); result.Proto != "modbus" || len(result.Events) != 1 {
		t.Fatalf("late evidence did not enable an uncommitted flow: %+v", result)
	}
	next := *c.Evidence
	next.Reply.Source = netip.AddrPortFrom(next.Reply.Source.Addr(), 20000)
	state.Connection.Store(&flow.Connection{Status: "resolved", Evidence: &next})
	if result := manager.Inspect(state, pkt); result.Proto != "modbus" || len(result.Events) != 1 {
		t.Fatalf("switched an existing Modbus stream to DNP3: %+v", result)
	}
	owner := &observationContext{states: [2]*flow.State{state}, selected: true, legacy: manager}
	if !legacyDecodes(owner, identify.Modbus) || legacyDecodes(owner, identify.DNP3) {
		t.Fatal("passive ownership ignored the committed decoder")
	}
	if _, err := manager.OnFlowEnd(state); err != nil {
		t.Fatal(err)
	}
	if result := manager.Inspect(state, &dpi.ParsedPacket{Proto: "tcp"}); result.Proto != "dnp3" {
		t.Fatalf("flow end did not retire dispatch selection: %+v", result)
	}
}

func TestNATSessionSelectionReleasedByFlowSweep(t *testing.T) {
	e, _ := newEnforceEngine(t, rules.ActionAllow)
	state := natPolicyStates(policyNAT())[0]
	state.IdleTimeout = time.Second
	e.flowMu.Lock()
	e.flows[state.Key.MapKey()] = state
	e.flowMu.Unlock()
	pkt := &dpi.ParsedPacket{Proto: "tcp", HasOffset: true, Session: "swept-without-EndStream", Dir: dpi.ClientToServer}
	if result := e.DPI().Inspect(state, pkt); result.Proto != "modbus" {
		t.Fatalf("did not commit session decoder: %+v", result)
	}
	e.sweepFlows(state.LastSeen.Add(2 * time.Second))
	e.flowMu.Lock()
	remaining := len(e.flows)
	e.flowMu.Unlock()
	if remaining != 0 {
		t.Fatal("flow was not swept")
	}
	next := policyNAT()
	evidence := *next.Evidence
	evidence.Reply.Source = netip.AddrPortFrom(evidence.Reply.Source.Addr(), 20000)
	next.Evidence = &evidence
	state.Connection.Store(next)
	if result := e.DPI().Inspect(state, pkt); result.Proto != "dnp3" {
		t.Fatalf("sweep retained session dispatch without EndStream: %+v", result)
	}
	e.DPI().DiscardFlow(state)
}

func TestNATTagBindingConcurrentEventSnapshots(t *testing.T) {
	e, _ := newEnforceEngine(t, rules.ActionAllow,
		tagEntry("backend", "backend", func(entry *rules.Entry) {
			entry.Protocols = []rules.Protocol{{Name: "tcp", Port: "502"}}
		}),
		tagEntry("public", "public", func(entry *rules.Entry) {
			entry.Protocols = []rules.Protocol{{Name: "tcp", Port: "1502"}}
		}))
	verified := policyNAT()
	unverified := &flow.Connection{Key: verified.Key, Status: "not_found", Evidence: verified.Evidence}
	state := natPolicyStates(verified)[0]
	e.bindTransport(state, verified)
	var wg sync.WaitGroup
	wg.Go(func() {
		for range 100 {
			e.bindTransport(state, unverified)
			e.bindTransport(state, verified)
		}
	})
	wg.Go(func() {
		for range 100 {
			e.recordTaggedEvents(state, nil, []dpi.Event{{FlowID: state.ID(), Proto: "modbus", Kind: "request"}})
		}
	})
	wg.Wait()
	list := e.Events().List(0)
	if len(list) != 100 {
		t.Fatalf("recorded %d events, want 100", len(list))
	}
	for _, event := range list {
		tags, ok := event.Attributes[events.KeyTags].([]string)
		if !ok || len(tags) != 1 || tags[0] != "backend" && tags[0] != "public" {
			t.Fatalf("incoherent tag snapshot: %+v", event)
		}
	}
}

func TestNATDecoderSupportsServicePorts(t *testing.T) {
	for _, decoder := range []dpi.Decoder{modbus.NewDecoder(), dnp3.NewDecoder(), cip.NewDecoder(), iec104.NewDecoder()} {
		ports, _ := decoder.(dpi.PortHinter).Ports()
		c := policyNAT()
		c.Evidence.Reply.Source = netip.AddrPortFrom(c.Evidence.Reply.Source.Addr(), ports[0])
		for _, state := range natPolicyStates(c) {
			if !decoder.Supports(state) {
				t.Fatalf("%T did not support verified service on %s", decoder, state.ID())
			}
		}
	}
}

func TestNATUnverifiedPolicyUsesWire(t *testing.T) {
	c := policyNAT()
	c.Status = "not_found"
	entry := clientToServer("wire", "502", rules.ActionDeny, rules.ICSPredicate{Protocol: "modbus", FunctionCode: []uint8{3}, Mode: "enforce"})
	entry.Sources = []string{"192.0.2.99/32"} // The translated wire client, not Original.Source.
	e, _ := newEnforceEngine(t, rules.ActionAllow, entry)
	state := natPolicyStates(c)[1]
	pkt := &dpi.ParsedPacket{Proto: "tcp", SrcPort: state.Key.SrcPort, DstPort: state.Key.DstPort, Payload: modbusADU(1, 3, 10, 2)}
	result := e.DPI().Inspect(state, pkt)
	if result.Err != nil || len(result.Events) != 1 {
		t.Fatalf("unverified egress leg did not decode: %+v", result)
	}
	_, ctx, denied := e.enforceDPIEvents(state, pkt, result.Events, false)
	if !denied || ctx.SrcIP.String() != "192.0.2.99" || ctx.Port != "502" {
		t.Fatalf("unverified egress leg did not decide in wire space: %+v", ctx)
	}
}

func TestNATPolicyIdentityTagsExclusionsAndIEC(t *testing.T) {
	c := policyNAT()
	e, _ := newEnforceEngine(t, rules.ActionAllow, tagEntry("backend-tag", "backend", func(entry *rules.Entry) {
		entry.Sources, entry.Destinations = []string{testClient + "/32"}, []string{testServer + "/32"}
		entry.Protocols = []rules.Protocol{{Name: "tcp", Port: "502"}}
	}))
	snap := *e.CurrentRules()
	snap.IdentityBindings = []rules.IdentityBinding{{IP: testClient, Identities: []string{"operator"}}}
	e.LoadRules(snap)
	e.dpiExclusions = []DPIExclusion{{Type: "ip", Value: testClient}}
	for _, state := range natPolicyStates(c) {
		pkt := &dpi.ParsedPacket{Proto: "tcp", SrcPort: state.Key.SrcPort, DstPort: state.Key.DstPort}
		ctx := singleEvalContext(t, &snap, state, pkt, dpi.Event{Proto: "modbus", Kind: "request"}, "", "")
		if !reflect.DeepEqual(ctx.Identities, []string{"operator"}) || !reflect.DeepEqual(e.flowTags(state), []string{"backend"}) || e.addressExclusion(state) != testClient {
			t.Fatal("a policy consumer used translated wire coordinates")
		}
		table := newIECTable("learn", &zoneCache{})
		table.snap, table.policy = &snap, rules.NewEvaluator(&snap)
		iecCtx := table.stateContext(state)
		if iecCtx.SrcIP.String() != testClient || iecCtx.DstIP.String() != testServer || iecCtx.Port != "502" {
			t.Fatalf("IEC context diverged: %+v", iecCtx)
		}
		wire := state.Key
		if wire.Dir == flow.DirReverse {
			wire = wire.Reversed()
		}
		s := &iecSession{id: "retired", flow: state, client: wire.Tuple().Source, server: wire.Tuple().Destination}
		// No session remains in the table at emission time.
		got := table.withSessionTags([]iecTelemetry{s.sessionEvent(outcomeAborted, nil, time.Now())})
		if !reflect.DeepEqual(got[0].Attributes[events.KeyTags], []string{"backend"}) {
			t.Fatalf("retired session lost service tags: %+v", got)
		}
	}
	listed := e.TagConnections([]conntrack.Entry{{Proto: "tcp", Src: testClient, Dst: "203.0.113.1", Sport: "41000", Dport: "1502",
		ReplySrc: testServer, ReplyDst: "192.0.2.99", ReplySport: "502", ReplyDport: "52000"}})
	if !reflect.DeepEqual(listed[0].Tags, []string{"backend"}) {
		t.Fatalf("kernel listing tags used public service: %+v", listed)
	}
}

func TestNATEgressDenialDeletesOriginalAndResetsWire(t *testing.T) {
	f := newResetFlow(t, 502)
	c := policyNAT()
	f.e.LoadRules(rules.Snapshot{Default: rules.ActionAllow, Firewall: []rules.Entry{
		clientToServer("backend-deny", "502", rules.ActionDeny, rules.ICSPredicate{Protocol: "modbus", FunctionCode: []uint8{6}, Mode: "enforce"}),
	}})
	egress := flow.TupleKey(c.Evidence.Reply, flow.DirReverse).Reversed().Tuple()
	deliver := func(pkt capture.Packet) capture.Decision {
		pkt.Token = capture.NewToken(1, firstCommandTokens.Add(1))
		d := f.e.handlePacketConnection(pkt, c, nil)
		verdict := capture.VerdictAccept
		if d.Action == capture.Drop {
			verdict = capture.VerdictDrop
		}
		f.e.hooks.onVerdict(pkt.Token, verdict, nil)
		return d
	}
	syn := transportWire(egress, time.Now(), nil)
	syn.TCP = capture.TCPMeta{Valid: true, Seq: 100, Flags: capture.TCPFlagSYN}
	syn.HasMark, syn.Mark = true, enforce.HandshakeMark
	if d := deliver(syn); d.Action != capture.Accept {
		t.Fatalf("SYN = %+v", d)
	}
	pkt := transportWire(egress, time.Now(), modbusADU(1, 6, 10, 2))
	pkt.TCP = capture.TCPMeta{Valid: true, Seq: 101, Ack: 9000, Flags: ackPsh}
	if d := deliver(pkt); d.Action != capture.Drop || d.Reason != reasonDPIDeny {
		t.Fatalf("denial = %+v", d)
	}
	drainResetWorker(t, f.e)
	select {
	case req := <-f.deletes:
		want := conntrack.DeleteRequest{Proto: "tcp", Src: testClient, Dst: "203.0.113.1", Sport: 41000, Dport: 1502}
		if req != want {
			t.Fatalf("delete = %+v, want original %+v", req, want)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("no CT deletion")
	}
	want := []session.Reset{{Src: egress.Source, Dst: egress.Destination, Seq: 101}, {Src: egress.Destination, Dst: egress.Source, Seq: 9000}}
	if got := f.inj.Resets(); !reflect.DeepEqual(got, want) {
		t.Fatalf("resets left packet space: %+v, want %+v", got, want)
	}
}
