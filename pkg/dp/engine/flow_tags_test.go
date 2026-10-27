// SPDX-License-Identifier: Apache-2.0

package engine

import (
	"net"
	"net/netip"
	"reflect"
	"testing"
	"time"

	"github.com/tonylturner/containd/pkg/dp/capture"
	"github.com/tonylturner/containd/pkg/dp/conntrack"
	"github.com/tonylturner/containd/pkg/dp/events"
	"github.com/tonylturner/containd/pkg/dp/flow"
	"github.com/tonylturner/containd/pkg/dp/rules"
)

func tagEntry(id, label string, mut func(*rules.Entry)) rules.Entry {
	e := rules.Entry{ID: id, Action: rules.ActionTag, Tag: label}
	if mut != nil {
		mut(&e)
	}
	return e
}

// tagRules labels the test connection's server port 502 "plc", every flow
// "any", and port 503 "other".
func tagRules() []rules.Entry {
	return []rules.Entry{
		tagEntry("tag-plc", "plc", func(e *rules.Entry) {
			e.Destinations = []string{testServer + "/32"}
			e.Protocols = []rules.Protocol{{Name: "tcp", Port: "502"}}
		}),
		tagEntry("tag-any", "any", nil),
		tagEntry("tag-other", "other", func(e *rules.Entry) { e.Protocols = []rules.Protocol{{Name: "tcp", Port: "503"}} }),
	}
}

// Both directions of a connection carry the labels of the TAG rules that
// match its opener-oriented tuple, and so do the flow's events, the rule
// hit included. TAG decides nothing.
func TestFlowStateAndEventsCarryTags(t *testing.T) {
	read := clientToServer("modbus-read", "502", rules.ActionAllow, rules.ICSPredicate{Protocol: "modbus", FunctionCode: []uint8{3}})
	e, up := newEnforceEngine(t, rules.ActionDeny, append(tagRules(), read)...)
	handshake(e, 41000, 502)
	e.handlePacket(connSegment(false, 41000, 502, 100, ackPsh, modbusADU(1, 3, 0, 1)))
	e.handlePacket(connSegment(true, 41000, 502, 500, ackPsh, []byte{0, 1, 0, 0, 0, 5, 1, 3, 2, 0, 7}))
	if got := up.blockedAfter(e); len(got) != 0 {
		t.Fatalf("blocks = %v; the read is allowed", got)
	}
	want := []string{"any", "plc"}
	e.flowMu.Lock()
	states := 0
	for _, st := range e.flows {
		states++
		if !reflect.DeepEqual(st.Tags, want) {
			t.Errorf("%s state tags = %v, want %v", st.Key.Hash(), st.Tags, want)
		}
	}
	e.flowMu.Unlock()
	if states != 2 {
		t.Fatalf("flow states = %d, want both directions", states)
	}
	var modbus, hits int
	for _, ev := range e.Events().List(0) {
		switch {
		case ev.Proto == "modbus":
			modbus++
		case ev.Kind == "firewall.rule.hit":
			hits++
		default:
			continue
		}
		if got := ev.Attributes[events.KeyTags]; !reflect.DeepEqual(got, want) {
			t.Errorf("%s %s event tags = %v, want %v", ev.Proto, ev.Kind, got, want)
		}
	}
	if modbus < 2 || hits == 0 {
		t.Fatalf("modbus events = %d, rule hits = %d", modbus, hits)
	}

	// A connection to another port gets only the catch-all label.
	handshake(e, 41001, 1502)
	e.flowMu.Lock()
	defer e.flowMu.Unlock()
	for _, st := range e.flows {
		if st.Key.DstPort == 1502 || st.Key.SrcPort == 1502 {
			if !reflect.DeepEqual(st.Tags, []string{"any"}) {
				t.Errorf("port 1502 tags = %v", st.Tags)
			}
		}
	}
}

func TestTagConnections(t *testing.T) {
	e, _ := newEnforceEngine(t, rules.ActionDeny, tagRules()...)
	got := e.TagConnections([]conntrack.Entry{
		{Proto: "tcp", Src: testClient, Dst: testServer, Sport: "41000", Dport: "502"},
		{Proto: "tcp", Src: testClient, Dst: "192.0.2.9", Sport: "41000", Dport: "503"},
		{Proto: "icmp", Src: testClient, Dst: testServer},
		{Proto: "tcp", Src: "not-an-ip", Dst: testServer, Dport: "502"},
	})
	want := [][]string{{"any", "plc"}, {"any", "other"}, {"any"}, nil}
	for i := range want {
		if !reflect.DeepEqual(got[i].Tags, want[i]) || got[i].Proto == "" {
			t.Errorf("connection %d = %+v, want tags %v", i, got[i], want[i])
		}
	}
	var none *Engine
	if out := none.TagConnections([]conntrack.Entry{{Proto: "tcp"}}); len(out) != 1 || out[0].Tags != nil {
		t.Fatalf("nil engine = %+v", out)
	}
}

// IEC104 session events carry the labels of the session tuple under the
// table's current policy.
func TestIECSessionEventsCarryTags(t *testing.T) {
	snap := &rules.Snapshot{Firewall: append(tagRules(), tagEntry("tag-iec", "telecontrol", func(e *rules.Entry) {
		e.Protocols = []rules.Protocol{{Name: "tcp", Port: "2404"}}
	}))}
	table := newIECTable("enforce", &zoneCache{})
	table.snap, table.policy = snap, rules.NewEvaluator(snap)
	s := &iecSession{id: "s1", client: netip.MustParseAddrPort(testClient + ":40000"), server: netip.MustParseAddrPort(testServer + ":2404")}
	evs := table.withSessionTags([]events.Event{s.sessionEvent(outcomeAborted, nil, time.Now()), healthEvent(outcomeEnforceHealthy, "", time.Now())})
	if got := evs[0].Attributes[events.KeyTags]; !reflect.DeepEqual(got, []string{"any", "telecontrol"}) {
		t.Fatalf("session event tags = %v", got)
	}
	if _, ok := evs[1].Attributes[events.KeyTags]; ok {
		t.Fatal("a health event without a session tuple got tags")
	}
	table.policy = rules.NewEvaluator(&rules.Snapshot{})
	if evs := table.withSessionTags([]events.Event{s.sessionEvent(outcomeAborted, nil, time.Now())}); evs[0].Attributes[events.KeyTags] != nil {
		t.Fatal("tags without TAG rules")
	}
}

// A RESET rule decides an inspected message like DENY: the engine cannot
// reject a queued packet, so it drops it and blocks the flow.
func TestResetRuleDropsInspectedMessage(t *testing.T) {
	read := clientToServer("modbus-read", "502", rules.ActionAllow, rules.ICSPredicate{Protocol: "modbus", FunctionCode: []uint8{3}})
	reset := rules.Entry{ID: "reset-502", Protocols: []rules.Protocol{{Name: "tcp", Port: "502"}}, Action: rules.ActionReset}
	e, up := newEnforceEngine(t, rules.ActionAllow, read, reset)
	handshake(e, 41000, 502)
	if d := e.handlePacket(connSegment(false, 41000, 502, 100, ackPsh, modbusADU(1, 3, 0, 1))); d.Action != capture.Accept {
		t.Fatalf("read decision = %+v; ALLOW takes precedence over RESET", d)
	}
	if d := e.handlePacket(connSegment(false, 41000, 502, 112, ackPsh, modbusADU(2, 6, 1, 3))); d.Action != capture.Drop {
		t.Fatalf("write decision = %+v, want drop", d)
	}
	if got, want := up.blockedAfter(e), []string{testClient + ">" + testServer + "/tcp:502"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("blocks = %v, want %v", got, want)
	}
}

// A kernel-logged rule hit carries the labels of its connection, oriented
// on the opener by the packet's conntrack direction, under the applied
// snapshot. A hit whose packet did not decode has none.
func TestNFLogRuleHitsCarryTags(t *testing.T) {
	e, _ := newEnforceEngine(t, rules.ActionDeny, tagRules()...)
	hits := nflogRuleHits{e}
	client, server := net.ParseIP(testClient), net.ParseIP(testServer)
	request := flow.Key{SrcIP: client, DstIP: server, SrcPort: 41000, DstPort: 502, Proto: 6}
	reply := flow.Key{SrcIP: server, DstIP: client, SrcPort: 502, DstPort: 41000, Proto: 6, Dir: flow.DirReverse}
	hits.RuleHit(events.Event{Kind: "firewall.rule.hit", FlowID: request.Hash(), Attributes: map[string]any{"ruleId": "r"}}, &request)
	hits.RuleHit(events.Event{Kind: "firewall.rule.hit", FlowID: reply.Hash(), Attributes: map[string]any{"ruleId": "r"}}, &reply)
	hits.RuleHit(events.Event{Kind: "firewall.rule.hit", Attributes: map[string]any{"ruleId": "r"}}, nil)
	got := map[string]any{}
	for _, ev := range e.Events().List(0) {
		if ev.Kind == "firewall.rule.hit" {
			got[ev.FlowID] = ev.Attributes[events.KeyTags]
		}
	}
	want := map[string]any{request.Hash(): []string{"any", "plc"}, reply.Hash(): []string{"any", "plc"}, "": nil}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("rule hit tags = %v, want %v", got, want)
	}
	flows := map[string][]string{}
	for _, f := range e.Events().Flows(0) {
		flows[f.FlowID] = f.Tags
	}
	if !reflect.DeepEqual(flows[request.Hash()], []string{"any", "plc"}) || !reflect.DeepEqual(flows[reply.Hash()], []string{"any", "plc"}) {
		t.Fatalf("flow summaries = %v", flows)
	}
}
