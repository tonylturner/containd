// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 containd Authors

package engine

import (
	"net"
	"net/netip"
	"reflect"
	"testing"
	"time"

	"github.com/tonylturner/containd/pkg/dp/dpi"
	"github.com/tonylturner/containd/pkg/dp/events"
	"github.com/tonylturner/containd/pkg/dp/flow"
	"github.com/tonylturner/containd/pkg/dp/ics"
	"github.com/tonylturner/containd/pkg/dp/ics/eventfields"
	"github.com/tonylturner/containd/pkg/dp/rules"
)

func undecodedEvent(proto string, both bool) dpi.Event {
	ev := dpi.Event{Proto: proto, Kind: "request", Attributes: map[string]any{
		eventfields.KeyUndecoded: []string{proto + ".test"},
		eventfields.KeyAPDUID:    "apdu",
		eventfields.KeySessionID: "session",
	}}
	if both {
		// Equal codes must still produce independent alert identities.
		ev.Attributes[eventfields.KeyConformance] = []string{proto + ".test"}
	}
	return ev
}

func assertUndecodedAlerts(t *testing.T, e *Engine, ev dpi.Event, action string) {
	t.Helper()
	seen := map[string]bool{}
	for _, alert := range e.Events().List(0) {
		if alert.Kind != "alert" {
			continue
		}
		id, _ := alert.Attributes["rule_id"].(string)
		key := eventfields.KeyUndecoded
		if id == "ics-conformance" {
			key = eventfields.KeyConformance
		}
		want, _ := eventfields.Strings(ev.Attributes, key)
		got, _ := eventfields.Strings(alert.Attributes, key)
		if seen[id] || id != "ics-"+key || len(want) == 0 || !reflect.DeepEqual(got, want) ||
			alert.Attributes["action"] != action ||
			alert.Attributes["message"] != ev.Proto+" "+key+" "+ev.Proto+".test: "+action {
			t.Fatalf("unexpected alert: %+v", alert)
		}
		seen[id] = true
	}
	wantCount := 1
	if _, ok := ev.Attributes[eventfields.KeyConformance]; ok {
		wantCount++
	}
	if len(seen) != wantCount {
		t.Fatalf("alert IDs = %v, want %d", seen, wantCount)
	}
}

func TestUndecodedPolicy(t *testing.T) {
	for _, proto := range []string{"modbus", "dnp3", "cip"} {
		for _, parsing := range []string{"tolerant", "strict"} {
			for _, mode := range []string{"enforce", "learn"} {
				for _, both := range []bool{false, true} {
					name := proto + "/" + parsing + "/" + mode
					if both {
						name += "/both"
					}
					t.Run(name, func(t *testing.T) {
						e, err := New(Config{DPIMode: "enforce", DPIICSParsing: map[string]string{proto: parsing}})
						if err != nil {
							t.Fatal(err)
						}
						e.LoadRules(rules.Snapshot{Default: rules.ActionAllow, Firewall: []rules.Entry{{
							ID: "allow", Action: rules.ActionAllow, ICS: rules.ICSPredicate{Protocol: proto, Mode: mode},
						}}})
						st := conformanceState()
						ports := map[string]uint16{"modbus": ics.ModbusPort, "dnp3": ics.DNP3Port, "cip": ics.CIPPort}
						st.Key.DstPort = ports[proto]
						pkt := &dpi.ParsedPacket{Proto: "tcp", SrcPort: st.Key.SrcPort, DstPort: st.Key.DstPort}
						ev := undecodedEvent(proto, both)
						v, _, drop := e.enforceDPIEvents(st, pkt, []dpi.Event{ev}, false)
						wantDrop := parsing == "strict" && mode == "enforce"
						if drop != wantDrop || (drop && v.Reason != reasonNonconformant) {
							t.Fatalf("drop=%v verdict=%+v, want drop=%v", drop, v, wantDrop)
						}
						action := "passed"
						if wantDrop {
							action = "dropped and reset"
						} else if parsing == "strict" {
							action = "would drop"
						}
						assertUndecodedAlerts(t, e, ev, action)
						var decisions []events.Event
						for _, event := range e.Events().List(0) {
							if event.Kind == eventfields.KindDecision {
								decisions = append(decisions, event)
							}
						}
						if parsing == "tolerant" {
							if len(decisions) != 0 {
								t.Fatalf("tolerant ALLOW added decisions: %+v", decisions)
							}
						} else {
							want := decisionWouldDrop
							if wantDrop {
								want = decisionDeny
							}
							if len(decisions) != 1 || decisions[0].Attributes[eventfields.KeyDecision] != want ||
								decisions[0].Attributes[eventfields.KeyMode] != mode {
								t.Fatalf("decisions = %+v, want one %s/%s", decisions, want, mode)
							}
							for key, value := range ev.Attributes {
								if key == eventfields.KeyConformance || key == eventfields.KeyUndecoded {
									if !reflect.DeepEqual(decisions[0].Attributes[key], value) {
										t.Fatalf("decision lost %s", key)
									}
								}
							}
						}
						// Repeated undecoded codes do not repeat either alert.
						e.enforceDPIEvents(st, pkt, []dpi.Event{ev}, false)
						assertUndecodedAlerts(t, e, ev, action)
					})
				}
			}
		}
	}
}

func TestIECUndecodedPolicy(t *testing.T) {
	for _, parsing := range []ics.Parsing{ics.Tolerant, ics.Strict} {
		for _, mode := range []string{"enforce", "learn"} {
			for _, both := range []bool{false, true} {
				name := string(parsing) + "/" + mode
				if both {
					name += "/both"
				}
				t.Run(name, func(t *testing.T) {
					tab := newIECTable("enforce", &zoneCache{})
					snap := iecBroadPolicy(mode)
					tab.setPolicy(&snap)
					tab.parsing = parsing
					client := netip.MustParseAddrPort("10.60.60.10:40000")
					server := netip.MustParseAddrPort("10.30.30.30:2404")
					s := &iecSession{id: "session", client: client, server: server, mode: mode, ctx: tab.sessionCtx(client, server)}
					ev := undecodedEvent("iec104", both)
					j := tab.judgeLocked(s, []dpi.Event{ev}, time.Now())
					wantDrop := parsing == ics.Strict && mode == "enforce"
					want, action := decisionAllow, "passed"
					if wantDrop {
						want, action = decisionDeny, "dropped and reset"
					} else if parsing == ics.Strict {
						want, action = decisionWouldDrop, "would drop"
					}
					if j.denied != wantDrop || len(j.events) != 1 || len(j.findings) != 1 ||
						j.events[0].Attributes[eventfields.KeyDecision] != want {
						t.Fatalf("judgement = %+v, want one %s", j, want)
					}
					for _, key := range inspectionFindingKeys {
						if !reflect.DeepEqual(j.events[0].Attributes[key], ev.Attributes[key]) {
							t.Fatalf("decision lost %s", key)
						}
					}
					e, err := New(Config{})
					if err != nil {
						t.Fatal(err)
					}
					st := flow.NewState(flow.Key{SrcIP: net.IP(client.Addr().AsSlice()), DstIP: net.IP(server.Addr().AsSlice()),
						SrcPort: client.Port(), DstPort: server.Port(), Proto: ics.TCP}, time.Now())
					e.recordConformanceAlert(st, &dpi.ParsedPacket{Proto: "tcp"}, j.findings[0].ev, action)
					assertUndecodedAlerts(t, e, ev, action)
					for _, alert := range e.Events().List(0) {
						if alert.Attributes[eventfields.KeyAPDUID] != "apdu" || alert.Attributes[eventfields.KeySessionID] != "session" {
							t.Fatal("alert lost IEC identity")
						}
					}
				})
			}
		}
	}
}

func TestUndecodedDecodedDeny(t *testing.T) {
	for _, mode := range []string{"enforce", "learn"} {
		t.Run(mode, func(t *testing.T) {
			e, err := New(Config{DPIMode: "enforce", DPIICSParsing: map[string]string{"cip": "strict"}})
			if err != nil {
				t.Fatal(err)
			}
			e.LoadRules(rules.Snapshot{Default: rules.ActionAllow, Firewall: []rules.Entry{{
				ID: "deny", Action: rules.ActionDeny,
				ICS: rules.ICSPredicate{Protocol: "cip", Mode: mode, FunctionCode: []uint8{17}},
			}}})
			ev := undecodedEvent("cip", true)
			ev.Attributes[eventfields.KeyFunctionCode] = uint8(17)
			_, _, drop := e.enforceDPIEvents(conformanceState(), &dpi.ParsedPacket{Proto: "tcp", DstPort: 44818}, []dpi.Event{ev}, false)
			if drop != (mode == "enforce") {
				t.Fatalf("drop=%v, mode=%s", drop, mode)
			}
			var decisions []events.Event
			for _, event := range e.Events().List(0) {
				if event.Kind == eventfields.KindDecision {
					decisions = append(decisions, event)
				}
			}
			if len(decisions) != 1 || decisions[0].Attributes[eventfields.KeyRuleID] != "deny" ||
				decisions[0].Attributes[eventfields.KeyReason] != reasonRule {
				t.Fatalf("decoded denial lost precedence: %+v", decisions)
			}
		})
	}
}

func TestUndecodedOutsideScope(t *testing.T) {
	for _, snapshot := range []bool{false, true} {
		e, err := New(Config{DPIMode: "enforce", DPIICSParsing: map[string]string{"cip": "strict"}})
		if err != nil {
			t.Fatal(err)
		}
		if snapshot {
			e.LoadRules(rules.Snapshot{Default: rules.ActionAllow})
		}
		ev := undecodedEvent("cip", false)
		// Event-store/JSON callers use []any, not []string.
		ev.Attributes[eventfields.KeyUndecoded] = []any{"cip.test"}
		st := conformanceState()
		pkt := &dpi.ParsedPacket{Proto: "tcp", DstPort: 44818}
		if _, _, drop := e.enforceDPIEvents(st, pkt, []dpi.Event{ev}, false); drop {
			t.Fatal("strict parsing denied outside an ICS scope")
		}
		assertUndecodedAlerts(t, e, ev, "passed")
	}
}
