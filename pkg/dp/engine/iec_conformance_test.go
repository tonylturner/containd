// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 containd Authors

package engine

import (
	"fmt"
	"reflect"
	"testing"

	"github.com/tonylturner/containd/pkg/dp/capture"
	"github.com/tonylturner/containd/pkg/dp/dpi"
	"github.com/tonylturner/containd/pkg/dp/events"
	"github.com/tonylturner/containd/pkg/dp/ics"
	"github.com/tonylturner/containd/pkg/dp/ics/eventfields"
	"github.com/tonylturner/containd/pkg/dp/ics/iec104"
	"github.com/tonylturner/containd/pkg/dp/rules"
)

// Nonconformant APDUs whose length octet frames them, through the real
// decoder: each is decoded content with a finding.
var (
	// GI activation with the reserved bit of control octet 3 set: type 100
	// and CA 1 are read; not safe-read.
	iecReservedGI = func() []byte {
		b := apdu(100, 6, 1, 0, 20)
		b[4] |= 0x01
		return b
	}()
	// Type 2 has no descriptor: the type byte is read, the objects are not.
	iecUnknownType = apdu(2, 3, 1, 1001, 0x02)
	// Two double commands in one ASDU: type 46 and CA 1 are read, no IOA.
	iecProfileTwoCommands = []byte{0x68, 18, 0, 0, 0, 0, 46, 2, 6, 0, 1, 0, 1, 0, 0, 0x01, 2, 0, 0, 0x01}
	// A start octet other than 0x68 loses the frame boundary.
	iecBadStart = []byte{0x69, 0x04, 0x07, 0, 0, 0}
)

// iecConformanceCase is one nonconformant APDU with the rule outcome the
// decoded fields give it under the "typed" policy.
type iecConformanceCase struct {
	name       string
	fromClient bool
	payload    []byte
	findings   []string
	typedRule  string // rule that decides it under iecTypedPolicy, "" for the default
}

var iecConformanceCases = []iecConformanceCase{
	{"reserved bits", true, iecReservedGI, []string{iec104.FindingReservedBits}, ""},
	{"unknown type", false, iecUnknownType, []string{iec104.FindingUnsupportedType}, "deny-type-2"},
	{"profile violation", true, iecProfileTwoCommands, []string{iec104.FindingProfileSQ}, ""},
}

func iecScoped(mode string, entries ...rules.Entry) rules.Snapshot {
	for i := range entries {
		entries[i].Sources, entries[i].Destinations = []string{"10.60.60.10/32"}, []string{"10.30.30.30/32"}
		entries[i].Protocols = []rules.Protocol{{Name: "tcp", Port: "2404"}}
		entries[i].ICS.Protocol, entries[i].ICS.Mode = iecProtocol, mode
		entries[i].Log = true
	}
	return rules.Snapshot{Default: rules.ActionDeny, Firewall: entries}
}

// iecBroadPolicy allows every IEC104 message.
func iecBroadPolicy(mode string) rules.Snapshot {
	return iecScoped(mode, rules.Entry{ID: "all", Action: rules.ActionAllow})
}

// iecTypedPolicy names fields: safe reads, one breaker command by IOA, and a
// DENY on the unknown type. Absent fields satisfy none of them.
func iecTypedPolicy(mode string) rules.Snapshot {
	return iecScoped(mode,
		rules.Entry{ID: "reads", Action: rules.ActionAllow, ICS: rules.ICSPredicate{ReadOnly: true}},
		rules.Entry{ID: "breaker", Action: rules.ActionAllow, ICS: rules.ICSPredicate{TypeIDs: []int{46}, CA: []uint16{1}, IOA: []rules.IOARange{{Start: 2001, End: 2001}}}},
		rules.Entry{ID: "deny-type-2", Action: rules.ActionDeny, ICS: rules.ICSPredicate{TypeIDs: []int{2}}},
	)
}

func newIECConformanceHarness(t *testing.T, mode string, parsing ics.Parsing, snap rules.Snapshot) *iecHarness {
	t.Helper()
	h := newIECHarness(t, mode)
	h.e.dpiMgr = dpi.NewManager(DefaultDecoders()...)
	h.e.iec.dpi = h.e.dpiMgr
	h.e.iec.newPolicy = newRulesPolicy
	h.e.LoadRules(snap)
	h.e.SetICSParsing(map[string]string{iecProtocol: string(parsing)})
	h.handshake()
	return h
}

// iecDecisions lists the decisions made on events with findings, oldest
// first.
func iecDecisions(h *iecHarness) []map[string]any {
	var out []map[string]any
	for _, ev := range h.eventsOf(eventfields.KindDecision) {
		if codes, _ := eventfields.Strings(ev.Attributes, eventfields.KeyConformance); len(codes) > 0 {
			out = append(out, ev.Attributes)
		}
	}
	return out
}

func assertIECAlert(t *testing.T, e *Engine, findings []string, action string) {
	t.Helper()
	alerts := findingEvents(e, "alert")
	if len(alerts) != 1 {
		t.Fatalf("conformance alerts = %+v, want one", alerts)
	}
	a := alerts[0]
	codes, _ := eventfields.Strings(a.Attributes, eventfields.KeyConformance)
	if a.Proto != "ids" || a.Attributes["rule_id"] != "ics-conformance" || a.Attributes["severity"] != "medium" ||
		a.Attributes["action"] != action || a.Attributes["protocol"] != iecProtocol || !reflect.DeepEqual(codes, findings) ||
		a.SrcIP == "" || a.FlowID == "" || a.Attributes[eventfields.KeySessionID] == "" || a.Attributes[eventfields.KeyAPDUID] == "" {
		t.Fatalf("conformance alert = %+v, want %v %s", a, findings, action)
	}
}

// TestIECConformanceMatrix: tolerant judges decoded fields, strict denies
// before ALLOW; an enforce envelope aborts, a learn envelope only reports.
func TestIECConformanceMatrix(t *testing.T) {
	for _, tc := range iecConformanceCases {
		for _, parsing := range []ics.Parsing{ics.Tolerant, ics.Strict} {
			for _, mode := range []string{"enforce", "monitor"} {
				for _, policy := range []string{"broad", "typed"} {
					t.Run(fmt.Sprintf("%s/%s/%s/%s", tc.name, parsing, mode, policy), func(t *testing.T) {
						snap := iecBroadPolicy(mode)
						if policy == "typed" {
							snap = iecTypedPolicy(mode)
						}
						h := newIECConformanceHarness(t, mode, parsing, snap)
						if _, d := h.send(true, startdtAct); d.Action != h.passingDisposition() {
							t.Fatalf("STARTDT act = %+v", d)
						}
						_, d := h.send(tc.fromClient, tc.payload)
						matched := policy == "broad" || tc.typedRule != ""
						allowed := policy == "broad"
						wantDrop := mode == "enforce" && (parsing == ics.Strict || !allowed)
						if (d.Action == capture.Drop) != wantDrop {
							t.Fatalf("decision=%+v want drop %v", d, wantDrop)
						}
						action := "passed"
						if wantDrop {
							action = "dropped and reset"
						} else if parsing == ics.Strict || mode == "monitor" {
							action = "would drop"
						}
						assertIECAlert(t, h.e, tc.findings, action)
						decs := iecDecisions(h)
						wantCount := 1
						if mode == "monitor" {
							wantCount = 1
							if matched {
								wantCount++
							}

						}
						if len(decs) != wantCount {
							t.Fatalf("decisions=%+v want %d", decs, wantCount)
						}
						for _, dec := range decs {
							codes, _ := eventfields.Strings(dec, eventfields.KeyConformance)
							if dec["mode"] != mode || !reflect.DeepEqual(codes, tc.findings) {
								t.Fatal(dec)
							}
							if dec["reason"] == reasonRule {
								id := tc.typedRule
								if policy == "broad" {
									id = "all"
								}
								decision := decisionDeny
								if allowed {
									decision = decisionAllow
								}
								if mode == "monitor" {
									decision = decisionWouldDrop
									if allowed {
										decision = decisionWouldAllow
									}
								}
								if dec["ruleId"] != id || dec["decision"] != decision {
									t.Fatalf("rule decision: %+v", dec)
								}
							} else if parsing == ics.Strict {
								decision := decisionDeny
								if mode == "monitor" {
									decision = decisionWouldDrop
								}
								if dec["reason"] != reasonNonconformant || dec["ruleId"] != nil || dec["scopeId"] == nil || dec["action"] != nil || dec["decision"] != decision {
									t.Fatalf("scope decision: %+v", dec)
								}
							} else {
								decision := decisionDeny
								if mode == "monitor" {
									decision = decisionWouldDrop
								}
								if dec["reason"] != reasonDefault || dec["decision"] != decision {
									t.Fatalf("default decision in %s: %+v, want %s", mode, dec, decision)
								}
							}
						}
						if wantDrop {
							if got := h.outcomes(); len(got) == 0 || got[0] != outcomeAborted {
								t.Fatalf("outcomes = %v, want aborted", got)
							}
						} else if len(h.outcomes()) != 0 || len(h.inj.Resets()) != 0 {
							t.Fatalf("on-wire effect without a drop: %v", h.outcomes())
						}
						if h.e.learnWatch.Load() != nil {
							t.Fatal("findings entered the learner")
						}
					})
				}
			}
		}
	}
}

// A strict deny carries the findings; a tolerant allow of nonconformant
// content keeps its decoded fields for the rules that named them.
func TestIECTolerantAllowMatchesDecodedFields(t *testing.T) {
	h := newIECConformanceHarness(t, "enforce", ics.Tolerant, iecScoped("enforce",
		rules.Entry{ID: "gi", Action: rules.ActionAllow, ICS: rules.ICSPredicate{TypeIDs: []int{100}, CA: []uint16{1}}}))
	if _, d := h.send(true, iecReservedGI); d.Action != h.passingDisposition() {
		t.Fatalf("reserved-bit GI under a typed ALLOW = %+v, want Accept", d)
	}
	decs := iecDecisions(h)
	if len(decs) != 1 || decs[0][eventfields.KeyRuleID] != "gi" || decs[0][eventfields.KeyDecision] != decisionAllow ||
		decs[0][eventfields.KeyTypeID] != uint8(100) {
		t.Fatalf("decisions = %+v", decs)
	}
	// readOnly never admits nonconformant content, even a GI.
	h2 := newIECConformanceHarness(t, "enforce", ics.Tolerant, iecScoped("enforce",
		rules.Entry{ID: "reads", Action: rules.ActionAllow, ICS: rules.ICSPredicate{ReadOnly: true}}))
	if _, d := h2.send(true, iecReservedGI); d.Action != capture.Drop {
		t.Fatalf("reserved-bit GI under readOnly = %+v, want Drop", d)
	}
}

// One alert per connection per code: repeats count, a new code alerts, and
// a new incarnation on the same tuple starts over.
func TestIECConformanceAlertOncePerConnection(t *testing.T) {
	h := newIECConformanceHarness(t, "enforce", ics.Tolerant, iecBroadPolicy("enforce"))
	for i := 0; i < 3; i++ {
		if _, d := h.send(true, iecReservedGI); d.Action != h.passingDisposition() {
			t.Fatalf("send %d = %+v", i, d)
		}
	}
	if got := findingEvents(h.e, "alert"); len(got) != 1 {
		t.Fatalf("alerts after repeats = %d, want 1", len(got))
	}
	if _, d := h.send(true, iecProfileTwoCommands); d.Action != h.passingDisposition() {
		t.Fatalf("profile APDU = %+v", d)
	}
	alerts := findingEvents(h.e, "alert")
	if len(alerts) != 2 {
		t.Fatalf("alerts after a new code = %d, want 2", len(alerts))
	}
	// The client closes with a RST at its forwarded end; the next SYN on the
	// tuple opens a new incarnation whose findings alert again.
	if d := h.e.handlePacket(h.pkt(true, capture.TCPFlagRST|capture.TCPFlagACK, h.cSeq, h.sSeq, nil)); d.Action != h.passingDisposition() {
		t.Fatalf("RST = %+v", d)
	}
	h.clientISN, h.serverISN = testClientISN-1000, testServerISN+1000
	h.cSeq, h.sSeq = h.clientISN+1, h.serverISN+1
	for _, p := range []capture.Packet{
		h.pkt(true, capture.TCPFlagSYN, h.clientISN, 0, nil),
		h.pkt(false, capture.TCPFlagSYN|capture.TCPFlagACK, h.serverISN, h.cSeq, nil),
		h.pkt(true, capture.TCPFlagACK, h.cSeq, h.sSeq, nil),
	} {
		if d := h.e.handlePacket(p); d.Action != h.passingDisposition() {
			t.Fatalf("second handshake %+v: %+v", p.TCP, d)
		}
	}
	if _, d := h.send(true, iecReservedGI); d.Action != h.passingDisposition() {
		t.Fatalf("second incarnation = %+v", d)
	}
	if got := findingEvents(h.e, "alert"); len(got) != 3 {
		t.Fatalf("alerts after a new incarnation = %d, want 3", len(got))
	}
}

// A lost frame boundary is not a finding: its malformed evidence is denied
// by the envelope, which resets the session in both parsing modes (enforce)
// and stops parsing without an alert (learn).
func TestIECFrameBoundaryLossResetsInBothModes(t *testing.T) {
	for _, parsing := range []ics.Parsing{ics.Tolerant, ics.Strict} {
		for _, mode := range []string{"enforce", "monitor"} {
			t.Run(string(parsing)+"/"+mode, func(t *testing.T) {
				h := newIECConformanceHarness(t, mode, parsing, iecBroadPolicy(mode))
				_, d := h.send(true, iecBadStart)
				if mode == "enforce" {
					if d.Action != capture.Drop {
						t.Fatalf("bad start octet = %+v, want Drop", d)
					}
					sessions := h.eventsOf(eventfields.KindSession)
					if len(sessions) == 0 || sessions[0].Attributes[eventfields.KeyOutcome] != outcomeAborted ||
						sessions[0].Attributes[eventfields.KeyReason] != abortDeny.name {
						t.Fatalf("session events = %+v, want aborted/deny", sessions)
					}
				} else if d.Action != h.passingDisposition() || len(h.outcomes()) != 0 {
					t.Fatalf("learn bad start octet = %+v, outcomes %v", d, h.outcomes())
				}
				var decs []events.Event
				for _, ev := range h.eventsOf(eventfields.KindDecision) {
					if ev.Attributes["reason"] == reasonMalformed {
						decs = append(decs, ev)
					}
				}
				if len(decs) != 1 || decs[0].Attributes[eventfields.KeyReason] != reasonMalformed || len(iecDecisions(h)) != 0 {
					t.Fatalf("decisions = %+v, want one malformed denial without findings", decs)
				}
				if alerts := findingEvents(h.e, "alert"); len(alerts) != 0 {
					t.Fatalf("frame loss raised conformance alerts: %+v", alerts)
				}
			})
		}
	}
}

// A parsing change applies to the next decision; it resets nothing by
// itself.
func TestIECParsingChangeAppliesToNewDecisions(t *testing.T) {
	h := newIECConformanceHarness(t, "enforce", ics.Tolerant, iecBroadPolicy("enforce"))
	if _, d := h.send(true, iecReservedGI); d.Action != h.passingDisposition() {
		t.Fatalf("tolerant = %+v", d)
	}
	h.e.SetICSParsing(map[string]string{iecProtocol: string(ics.Strict)})
	if got := h.outcomes(); len(got) != 0 {
		t.Fatalf("mode change retired the session: %v", got)
	}
	if _, d := h.send(true, iecReservedGI); d.Action != capture.Drop {
		t.Fatalf("strict after the change = %+v, want Drop", d)
	}
	decs := iecDecisions(h)
	if len(decs) != 2 || decs[0][eventfields.KeyDecision] != decisionAllow || decs[1][eventfields.KeyReason] != reasonNonconformant {
		t.Fatalf("decisions = %+v", decs)
	}
	if got := h.outcomes(); len(got) == 0 || got[0] != outcomeAborted {
		t.Fatalf("outcomes = %v, want aborted by the strict decision", got)
	}
}
