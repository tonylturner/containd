// SPDX-License-Identifier: Apache-2.0
package engine

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/tonylturner/containd/pkg/dp/dpi"
	"github.com/tonylturner/containd/pkg/dp/events"
	"github.com/tonylturner/containd/pkg/dp/ics"
	"github.com/tonylturner/containd/pkg/dp/rules"
)

func TestRuleModesMixedMatrix(t *testing.T) {
	for _, proto := range []string{"modbus", "iec104"} {
		for _, reverse := range []bool{false, true} {
			for _, monitor := range []rules.Action{rules.ActionAllow, rules.ActionDeny} {
				for _, enforce := range []rules.Action{rules.ActionAllow, rules.ActionDeny} {
					for _, strict := range []bool{false, true} {
						t.Run(fmt.Sprintf("%s/reverse=%t/%s/%s/strict=%t", proto, reverse, monitor, enforce, strict), func(t *testing.T) {
							e, err := New(Config{DPIEnabled: true, DPIMode: "enforce"})
							if err != nil {
								t.Fatal(err)
							}
							mid, eid := "a-monitor", "z-enforce"
							if reverse {
								mid, eid = eid, mid
							}
							snap := rules.Snapshot{Version: "matrix", Default: rules.ActionAllow, Firewall: []rules.Entry{
								{ID: mid, Action: monitor, ICS: rules.ICSPredicate{Protocol: proto, Mode: "monitor"}},
								{ID: eid, Action: enforce, ICS: rules.ICSPredicate{Protocol: proto, Mode: "enforce"}},
							}}
							if err := e.ApplyRules(context.Background(), snap); err != nil {
								t.Fatal(err)
							}
							parsing := "tolerant"
							if strict {
								parsing = "strict"
							}
							e.SetICSParsing(map[string]string{proto: parsing})
							ev := dpi.Event{Proto: proto, Kind: "request", Attributes: map[string]any{"function_code": uint8(3), "apci_type": "I", "type_id": uint8(46), "ca": uint16(1), "apdu_id": "msg", "direction": "request"}}
							if strict {
								ev.Attributes["conformance"] = []string{proto + ".test"}
							}
							wantDrop := strict || enforce == rules.ActionDeny
							if proto == "modbus" {
								st := conformanceState()
								st.Key.DstPort = 502
								_, _, drop := e.enforceDPIEvents(st, &dpi.ParsedPacket{Proto: "tcp", DstPort: 502}, []dpi.Event{ev}, false)
								if drop != wantDrop {
									t.Fatalf("drop=%t want %t", drop, wantDrop)
								}
							} else {
								tab := e.iec
								tab.parsing = ics.Parsing(parsing)
								client := netip.MustParseAddrPort("10.60.60.10:40000")
								server := netip.MustParseAddrPort("10.30.30.30:2404")
								s := &iecSession{id: "matrix", client: client, server: server, mode: "enforce", ctx: tab.sessionCtx(client, server)}
								// Two objects in the same APDU still count as one message.
								j := tab.judgeLocked(s, []dpi.Event{ev, ev}, time.Now())
								if j.denied != wantDrop {
									t.Fatalf("denied=%t want %t", j.denied, wantDrop)
								}
								for _, d := range j.events {
									e.eventStore.Append(d.Event)
								}
							}
							counts := e.ShadowCounters()
							if !counts.Available || len(counts.Rules) != 1 || counts.Rules[0].RuleID != mid || counts.Rules[0].ShadowMatches != 1 {
								t.Fatalf("counts: %+v", counts)
							}
							c := counts.Rules[0]
							if (monitor == rules.ActionAllow && (c.WouldAllow != 1 || c.WouldDeny != 0)) || (monitor == rules.ActionDeny && (c.WouldDeny != 1 || c.WouldAllow != 0)) {
								t.Fatalf("action counts: %+v", c)
							}
							found := 0
							scope := 0
							for _, d := range e.Events().List(0) {
								if d.Kind != "ics.decision" {
									continue
								}
								if d.Attributes["ruleId"] == mid {
									found++
									if d.Attributes["mode"] != "monitor" || d.Attributes["decision"] != shadowDecision(&snap.Firewall[0]) || d.Attributes["action"] != string(monitor) || d.Attributes["reason"] != "rule" {
										t.Fatalf("shadow: %+v", d)
									}
								}
								if d.Attributes["reason"] == reasonNonconformant {
									scope++
									if d.Attributes["scopeId"] != eid || d.Attributes["ruleId"] != nil || d.Attributes["action"] != nil || d.Attributes["findingCode"] != proto+".test" || d.Attributes["decision"] != "deny" {
										t.Fatalf("scope: %+v", d)
									}
								}
							}
							if found != 1 || strict && scope == 0 {
								t.Fatalf("shadow=%d scope=%d", found, scope)
							}
						})
					}
				}
			}
		}
	}
}

func TestRuleModesInheritInstalledGlobal(t *testing.T) {
	e, err := New(Config{DPIEnabled: true, DPIMode: "enforce"})
	if err != nil {
		t.Fatal(err)
	}
	for _, mode := range []string{"monitor", "enforce"} {
		snap := rules.Snapshot{Version: mode, DPIMode: mode, Firewall: []rules.Entry{
			{ID: "generic", Action: rules.ActionDeny, ICS: rules.ICSPredicate{Protocol: "modbus"}},
			{ID: "iec", Action: rules.ActionDeny, ICS: rules.ICSPredicate{Protocol: "iec104"}},
		}}
		if err := e.ApplyRules(context.Background(), snap); err != nil {
			t.Fatal(err)
		}
		if got := e.effectiveMode(&snap.Firewall[0]); got != mode {
			t.Fatalf("generic mode %s want %s", got, mode)
		}
		e.iec.mu.Lock()
		matched, got := e.iec.envelopeLocked(rules.EvalContext{Proto: "tcp", Port: "2404"})
		e.iec.mu.Unlock()
		if !matched || got != mode {
			t.Fatalf("IEC envelope matched=%t mode=%s want %s", matched, got, mode)
		}
		want := 0
		if mode == "monitor" {
			want = 2
		}
		if got := len(e.ShadowCounters().Rules); got != want {
			t.Fatalf("monitor partition size %d want %d", got, want)
		}
		for _, covered := range e.ICSCoverage() {
			if covered.Mode != mode {
				t.Fatalf("coverage inherited a different mode: %+v", covered)
			}
		}
	}
}

func TestShadowCountersInstallResetRetention(t *testing.T) {
	e, err := New(Config{DPIEnabled: true})
	if err != nil {
		t.Fatal(err)
	}
	if e.ShadowCounters().Available {
		t.Fatal("available before apply")
	}
	snap := rules.Snapshot{Version: "one", Default: rules.ActionAllow, Firewall: []rules.Entry{
		{ID: "trial", Action: rules.ActionDeny, ICS: rules.ICSPredicate{Protocol: "modbus", Mode: "monitor"}},
		{ID: "zero", Action: rules.ActionAllow, ICS: rules.ICSPredicate{Protocol: "modbus", Mode: "monitor", FunctionCode: []uint8{6}}},
	}}
	if err := e.ApplyRules(context.Background(), snap); err != nil {
		t.Fatal(err)
	}
	st := conformanceState()
	st.Key.DstPort = 502
	ev := dpi.Event{Proto: "modbus", Kind: "request", Attributes: map[string]any{"function_code": uint8(3)}}
	e.enforceDPIEvents(st, &dpi.ParsedPacket{Proto: "tcp", DstPort: 502}, []dpi.Event{ev}, false)
	first := e.ShadowCounters()
	if len(first.Rules) != 2 || first.Rules[0].ShadowMatches != 1 || first.Rules[1].ShadowMatches != 0 {
		t.Fatal(first)
	}
	bad := rules.Snapshot{Version: "bad", Firewall: []rules.Entry{{ICS: rules.ICSPredicate{Protocol: "not-supported"}}}}
	if err := e.ApplyRules(context.Background(), bad); err == nil {
		t.Fatal("bad apply accepted")
	}
	kept := e.ShadowCounters()
	if kept.SnapshotVersion != "one" || !kept.Since.Equal(*first.Since) || kept.Rules[0].ShadowMatches != 1 {
		t.Fatal(kept)
	}
	snap.Version = "two"
	snap.Firewall[0].ICS.FunctionCode = []uint8{6}
	if err := e.ApplyRules(context.Background(), snap); err != nil {
		t.Fatal(err)
	}
	reset := e.ShadowCounters()
	if reset.SnapshotVersion != "two" || reset.Rules[0].ShadowMatches != 0 || reset.Since.Before(*first.Since) {
		t.Fatal(reset)
	}
	// A late old-generation observation cannot charge the new policy.
	old := &rules.Snapshot{Version: "one"}
	e.countShadow(old, &snap.Firewall[0])
	if e.ShadowCounters().Rules[0].ShadowMatches != 0 {
		t.Fatal("old snapshot charged new counts")
	}
}

func TestShadowDNP3ObjectsCountOnce(t *testing.T) {
	e := &Engine{eventStore: events.NewStore(100)}
	snap := &rules.Snapshot{Version: "objects", Default: rules.ActionAllow, Firewall: []rules.Entry{{ID: "all", Action: rules.ActionDeny, ICS: rules.ICSPredicate{Protocol: "dnp3", Mode: "monitor"}}}}
	e.ruleSnap.Install(snap, time.Now())
	ev := dpi.Event{Proto: "dnp3", Kind: "request", Attributes: predicateAttrs("dnp3")}
	st := conformanceState()
	st.Key.DstPort = 20000
	st.Key.SrcIP = net.ParseIP("10.60.60.10")
	pkt := &dpi.ParsedPacket{Proto: "tcp", DstPort: 20000}
	ctxs := evalContextsFromDPIEvent(snap, st, pkt, ev, "", "")
	if len(ctxs) == 0 {
		t.Fatal("no decoded context")
	}
	e.observeMonitor(snap, e.ruleSnap.Evaluator(), st, pkt, ev, append(ctxs, ctxs...))
	if e.ShadowCounters().Rules[0].ShadowMatches != 1 {
		t.Fatal("object-counted message")
	}
}

func shadowHits(e *Engine, id string) int {
	n := 0
	for _, ev := range e.Events().List(0) {
		if ev.Kind == "ics.decision" && ev.Attributes["ruleId"] == id && ev.Attributes["mode"] == "monitor" {
			n++
		}
	}
	return n
}
