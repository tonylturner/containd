// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 containd Authors

package engine

import (
	"net"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/tonylturner/containd/pkg/dp/capture"
	"github.com/tonylturner/containd/pkg/dp/dpi"
	"github.com/tonylturner/containd/pkg/dp/events"
	"github.com/tonylturner/containd/pkg/dp/flow"
	"github.com/tonylturner/containd/pkg/dp/ics/cip"
	"github.com/tonylturner/containd/pkg/dp/ics/dnp3"
	"github.com/tonylturner/containd/pkg/dp/ics/eventfields"
	"github.com/tonylturner/containd/pkg/dp/ics/modbus"
	"github.com/tonylturner/containd/pkg/dp/rules"
)

// Attach synthetic findings without depending on the decoder's classification
// of any particular wire nonconformance.
type findingDecoder struct{ dpi.StreamDecoder }

func (d findingDecoder) ParseStream(st *flow.State, v dpi.StreamView) (dpi.StreamResult, error) {
	res, err := d.StreamDecoder.ParseStream(st, v)
	for i := range res.Frames {
		for j := range res.Frames[i].Events {
			ev := &res.Frames[i].Events[j]
			ev.Attributes[eventfields.KeyConformance] = []string{ev.Proto + ".test"}
		}
	}
	return res, err
}

func findingEvents(e *Engine, kind string) []events.Event {
	var out []events.Event
	for _, ev := range e.Events().List(0) {
		if ev.Kind == kind {
			if codes, _ := eventfields.Strings(ev.Attributes, eventfields.KeyConformance); len(codes) > 0 {
				out = append(out, ev)
			}
		}
	}
	return out
}

func TestConformanceVerdictMatrix(t *testing.T) {
	for _, p := range resetProtocols() {
		for _, parsing := range []string{"tolerant", "strict"} {
			for _, mode := range []string{"enforce", "monitor"} {
				for _, decodedDeny := range []bool{false, true} {
					name := p.name + "/" + parsing + "/" + mode
					if decodedDeny {
						name += "/decoded-deny"
					}
					t.Run(name, func(t *testing.T) {
						f := newFCFlow(t, "ok", p.port)
						loadResetPolicy(f.e)
						snap := *f.e.CurrentRules()
						for i := range snap.Firewall {
							snap.Firewall[i].ICS.Mode = mode
						}
						f.e.LoadRules(snap)
						f.observeOnly = mode == "monitor"
						f.e.SetICSParsing(map[string]string{p.name: parsing})
						dec := map[string]dpi.StreamDecoder{"modbus": modbus.NewDecoder(), "dnp3": dnp3.NewDecoder(), "cip": cip.NewDecoder()}[p.name]
						f.e.dpiMgr = dpi.NewManager(findingDecoder{dec})
						f.syn()
						payload := p.read(1)
						if decodedDeny {
							payload = p.denied[0].frame
						}
						got := f.decide(0, ackPsh, payload)
						wantDrop := mode == "enforce" && (parsing == "strict" || decodedDeny)
						if (got.Action == capture.Drop) != wantDrop {
							t.Fatalf("decision = %+v; want drop %v", got, wantDrop)
						}
						action := "passed"
						if wantDrop {
							action = "dropped and reset"
							assertResetEvidence(t, f.e)
						} else {
							drainResetWorker(t, f.e)
							if parsing == "strict" {
								action = "would drop"
							}
							for _, ev := range f.e.Events().List(0) {
								if ev.Kind == eventfields.KindSession {
									t.Fatalf("monitor/pass reset evidence: %+v", ev)
								}
							}
						}
						alerts := findingEvents(f.e, "alert")
						if len(alerts) != 1 || alerts[0].Proto != "ids" ||
							alerts[0].Attributes["rule_id"] != "ics-conformance" ||
							alerts[0].Attributes["severity"] != "medium" ||
							alerts[0].Attributes["action"] != action ||
							!strings.Contains(alerts[0].Attributes["message"].(string), p.name+".test: "+action) ||
							alerts[0].SrcIP == "" || alerts[0].FlowID == "" {
							t.Fatalf("alerts = %+v, want %s", alerts, action)
						}
						allDecisions := findingEvents(f.e, eventfields.KindDecision)
						var decisions []events.Event
						for _, d := range allDecisions {
							if d.Attributes["mode"] == "monitor" && d.Attributes["reason"] == "rule" {
								if d.Attributes["ruleId"] == nil || d.Attributes["action"] == nil {
									t.Fatal("missing monitor attribution")
								}
								continue
							}
							decisions = append(decisions, d)
						}
						if parsing == "strict" || decodedDeny && mode == "enforce" {
							reason := reasonNonconformant
							if decodedDeny && parsing != "strict" {
								reason = "rule"
							}
							decision := decisionWouldDrop
							if wantDrop {
								decision = decisionDeny
							}
							if len(decisions) != 1 || decisions[0].Attributes[eventfields.KeyReason] != reason ||
								decisions[0].Attributes[eventfields.KeyDecision] != decision {
								t.Fatalf("decisions = %+v, want %s/%s", decisions, reason, decision)
							}
						} else if len(decisions) != 0 {
							t.Fatalf("tolerant allow decisions: %+v", decisions)
						}
						if len(f.e.Learner().Profiles()) != 0 || len(f.e.Inventory().List()) == 0 {
							t.Fatal("findings must remain in inventory but never enter learner")
						}
						select {
						case call := <-f.up.calls:
							t.Fatalf("unexpected service block: %s", call)
						default:
						}
					})
				}
			}
		}
	}
}

func conformanceState() *flow.State {
	return flow.NewState(flow.Key{SrcIP: net.ParseIP("10.0.0.1"), DstIP: net.ParseIP("10.0.0.2"),
		SrcPort: 40000, DstPort: 44818, Proto: 6}, time.Now())
}

func TestConformanceAlertDedupAndFlowEnd(t *testing.T) {
	e, err := New(Config{})
	if err != nil {
		t.Fatal(err)
	}
	st := conformanceState()
	pkt := &dpi.ParsedPacket{Proto: "tcp", SrcPort: 40000, DstPort: 44818}
	ev := dpi.Event{Proto: "cip", Kind: "session", Attributes: map[string]any{
		eventfields.KeyConformance: []string{"cip.a", "cip.b"},
	}}
	e.enforceDPIEvents(st, pkt, []dpi.Event{ev}, false)
	reverse := flow.NewState(st.Key.Reversed(), time.Now())
	e.enforceDPIEvents(reverse, pkt, []dpi.Event{ev}, false)
	ev.Attributes[eventfields.KeyConformance] = []string{"cip.b", "cip.c"}
	e.enforceDPIEvents(st, pkt, []dpi.Event{ev}, false)
	alerts := findingEvents(e, "alert")
	if len(alerts) != 2 {
		t.Fatalf("alerts = %+v", alerts)
	}
	codes, _ := eventfields.Strings(alerts[0].Attributes, eventfields.KeyConformance)
	if !reflect.DeepEqual(codes, []string{"cip.c"}) {
		t.Fatalf("new alert codes = %v", codes)
	}
	if e.conformance.conns[conformanceKey(st)].codes[inspectionFinding{field: eventfields.KeyConformance, code: "cip.b"}] != 3 {
		t.Fatal("repeats did not count")
	}
	other := flow.NewState(st.Key, time.Now())
	other.Key.SrcPort++
	e.enforceDPIEvents(other, pkt, []dpi.Event{ev}, false)
	if len(findingEvents(e, "alert")) != 3 {
		t.Fatal("independent connection was suppressed")
	}
	e.conformance.end(st, false)
	if len(e.conformance.conns) != 2 {
		t.Fatal("half-close discarded connection dedup")
	}
	e.conformance.end(reverse, false)
	if len(e.conformance.conns) != 1 {
		t.Fatal("full close retained dedup")
	}
	e.enforceDPIEvents(st, pkt, []dpi.Event{ev}, false)
	e.endFlowStream(st, pkt)
	if _, exists := e.conformance.conns[conformanceKey(st)]; exists {
		t.Fatal("flow retirement retained dedup")
	}
}

func TestConformanceBoundedState(t *testing.T) {
	var a conformanceAlerts
	st := conformanceState()
	codes := make([]string, conformanceMaxCodes+1)
	for i := range codes {
		codes[i] = strings.Repeat("a", i+1)
	}
	if len(a.fresh(st, eventfields.KeyConformance, codes)) != conformanceMaxCodes || a.suppressed != 1 {
		t.Fatal("per-connection code bound not applied")
	}
	for i := 0; i < conformanceMaxConnections-1; i++ {
		a.conns[strconv.Itoa(i)] = &conformanceConnection{}
	}
	other := flow.NewState(st.Key, time.Now())
	other.Key.SrcPort++
	if len(a.fresh(other, eventfields.KeyConformance, []string{"cip.a"})) != 0 {
		t.Fatal("connection bound not applied")
	}
}

func TestStrictFindingsBeforeAllowAndAfterDecodedDeny(t *testing.T) {
	f := newFCFlow(t, "ok", 502)
	f.e.SetICSParsing(map[string]string{"modbus": "strict"})
	f.e.dpiMgr = dpi.NewManager(findingDecoder{modbus.NewDecoder()})
	f.syn()
	payload := append(modbusADU(1, 3, 0, 2), modbusADU(2, 6, 1, 2)...)
	if got := f.decide(0, ackPsh, payload); got.Action != capture.Drop || got.Reason != reasonNonconformant {
		t.Fatalf("strict scope did not preempt decoded denial: %+v", got)
	}
	for _, ev := range findingEvents(f.e, eventfields.KindDecision) {
		if ev.Attributes[eventfields.KeyReason] != reasonNonconformant || ev.Attributes["scopeId"] == nil || ev.Attributes["ruleId"] != nil {
			t.Fatal("strict scope attribution lost")
		}
	}
}

func TestConformanceAlertReportsFailClosedOutcome(t *testing.T) {
	f := newFCFlow(t, "ok", 502)
	f.e.dpiMgr = dpi.NewManager(findingDecoder{modbus.NewDecoder()})
	f.syn()
	payload := append(modbusADU(1, 3, 0, 2), []byte{0, 2, 0, 0, 255, 255}...)
	if got := f.decide(0, ackPsh, payload); got.Action != capture.Drop || got.Reason != reasonStreamFailClosed {
		t.Fatalf("framing failure changed: %+v", got)
	}
	alerts := findingEvents(f.e, "alert")
	if len(alerts) != 1 || alerts[0].Attributes["action"] != "dropped and reset" {
		t.Fatalf("framing drop was reported as passed: %+v", alerts)
	}
	assertResetEvidence(t, f.e)
}

func TestStrictFindingsOwnDefaultDecision(t *testing.T) {
	for _, mode := range []string{"enforce", "monitor"} {
		t.Run(mode, func(t *testing.T) {
			e, err := New(Config{DPIMode: "enforce", DPIICSParsing: map[string]string{"cip": "strict"}})
			if err != nil {
				t.Fatal(err)
			}
			e.LoadRules(rules.Snapshot{Default: rules.ActionDeny, Firewall: []rules.Entry{{
				ID: "read", Action: rules.ActionAllow,
				ICS: rules.ICSPredicate{Protocol: "cip", FunctionCode: []uint8{0}, Mode: mode},
			}}})
			st := conformanceState()
			pkt := &dpi.ParsedPacket{Proto: "tcp", SrcPort: 40000, DstPort: 44818}
			ev := dpi.Event{Proto: "cip", Kind: "session", Attributes: map[string]any{
				eventfields.KeyConformance: []string{"cip.test"},
			}}
			_, _, drop := e.enforceDPIEvents(st, pkt, []dpi.Event{ev}, false)
			decisions := findingEvents(e, eventfields.KindDecision)
			if drop != (mode == "enforce") || len(decisions) != 1 ||
				decisions[0].Attributes[eventfields.KeyReason] != reasonNonconformant ||
				decisions[0].Attributes[eventfields.KeyMode] != mode {
				t.Fatalf("strict absent fields: drop=%v, decisions=%+v", drop, decisions)
			}
		})
	}
}

func TestEvalContextAbsentFieldsDoNotMatchZero(t *testing.T) {
	st := conformanceState()
	pkt := &dpi.ParsedPacket{Proto: "tcp", SrcPort: 40000, DstPort: 44818}
	for _, action := range []rules.Action{rules.ActionAllow, rules.ActionDeny, rules.ActionReset} {
		for _, predicate := range []rules.ICSPredicate{
			{Protocol: "cip", FunctionCode: []uint8{0}},
			{Protocol: "cip", ObjectClasses: []uint16{0}},
			{Protocol: "cip", UnitID: ptr8(0)},
			{Protocol: "cip", Addresses: []string{"0"}},
			{Protocol: "cip", ReadOnly: true},
			{Protocol: "cip", WriteOnly: true},
		} {
			ctx := singleEvalContext(t, nil, st, pkt, dpi.Event{Proto: "cip", Kind: "session"}, "", "")
			entry := rules.Entry{Action: action, ICS: predicate}
			if rules.PreviewMatch(entry, ctx) {
				t.Fatalf("absent field satisfied %+v", entry)
			}
		}
	}
	ev := dpi.Event{Proto: "cip", Kind: "request", Attributes: map[string]any{
		"function_code": uint8(0), "object_class": uint16(0),
	}}
	ctx := singleEvalContext(t, nil, st, pkt, ev, "", "")
	entry := rules.Entry{Action: rules.ActionAllow, ICS: rules.ICSPredicate{
		Protocol: "cip", FunctionCode: []uint8{0}, ObjectClasses: []uint16{0},
	}}
	if !rules.PreviewMatch(entry, ctx) {
		t.Fatal("decoded zero fields did not match")
	}
}
