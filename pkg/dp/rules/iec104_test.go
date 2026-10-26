// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

package rules

import (
	"net"
	"testing"
)

func TestICSPredicateEmptyCountsIEC104Fields(t *testing.T) {
	cases := map[string]ICSPredicate{
		"typeIds": {TypeIDs: []int{46}},
		"classes": {Classes: []string{"control"}},
		"ca":      {CA: []uint16{1}},
		"ioa":     {IOA: []IOARange{{Start: 1, End: 2}}},
	}
	for name, pred := range cases {
		if icsPredicateEmpty(pred) {
			t.Fatalf("%s: predicate with only %s must not be empty", name, name)
		}
	}
	if !icsPredicateEmpty(ICSPredicate{}) {
		t.Fatal("zero predicate must be empty")
	}
}

const (
	iecClient = "10.60.60.10"
	iecServer = "10.30.30.30"
)

func iecEntry(id string, action Action, ics ICSPredicate) Entry {
	ics.Protocol = ProtocolIEC104
	return Entry{
		ID:           id,
		SourceZones:  []string{"lan4"},
		DestZones:    []string{"lan1"},
		Sources:      []string{iecClient + "/32"},
		Destinations: []string{iecServer + "/32"},
		Protocols:    []Protocol{{Name: "tcp", Port: "2404"}},
		ICS:          ics,
		Action:       action,
	}
}

// euPolicy is the spec §12.4 rule block behind a broad L4 ALLOW on 2404
// and an ALLOW default, neither of which may take part in IEC evaluation.
func euPolicy() *Snapshot {
	return &Snapshot{
		Default: ActionAllow,
		Firewall: []Entry{
			{ID: "l4-any-2404", Protocols: []Protocol{{Name: "tcp", Port: "2404"}}, Action: ActionAllow},
			iecEntry("cc-rtu-iec104-session", ActionAllow, ICSPredicate{ReadOnly: true, Mode: "enforce"}),
			iecEntry("cc-rtu-breaker-command", ActionAllow, ICSPredicate{
				TypeIDs: []int{46}, Classes: []string{"control"}, Direction: "request",
				CA: []uint16{1}, IOA: []IOARange{{Start: 2001, End: 2001}}, Mode: "enforce",
			}),
			iecEntry("rtu-cc-command-confirm", ActionAllow, ICSPredicate{Classes: []string{"control"}, Direction: "response", Mode: "enforce"}),
			iecEntry("deny-other-iec104", ActionDeny, ICSPredicate{Mode: "enforce"}),
		},
	}
}

// sessionCtx builds the opener-oriented session tuple that L4 supplies
// for every IEC event, whatever the wire direction.
func sessionCtx(direction string, obj IEC104Context) EvalContext {
	return EvalContext{
		SrcZone: "lan4",
		DstZone: "lan1",
		SrcIP:   net.ParseIP(iecClient),
		DstIP:   net.ParseIP(iecServer),
		Proto:   "tcp",
		Port:    "2404",
		ICS:     &ICSContext{Protocol: ProtocolIEC104, Direction: direction, IEC104: &obj},
	}
}

func u8(v uint8) *uint8    { return &v }
func u16(v uint16) *uint16 { return &v }
func u32(v uint32) *uint32 { return &v }

func iFrame(typeID uint8, class string, ca uint16, ioa uint32, safeRead bool) IEC104Context {
	return IEC104Context{APCIType: "I", TypeID: u8(typeID), CA: u16(ca), IOA: u32(ioa), Class: class, SafeRead: safeRead}
}

func TestEvaluateIEC104EUPolicy(t *testing.T) {
	ev := NewEvaluator(euPolicy())
	broadcastGI := iFrame(100, "system", 65535, 0, true)
	broadcastGI.Broadcast = true
	cases := []struct {
		name      string
		direction string
		obj       IEC104Context
		want      Action
		rule      string
	}{
		{"GI request", "request", iFrame(100, "system", 1, 0, true), ActionAllow, "cc-rtu-iec104-session"},
		{"single-point monitor telemetry", "response", iFrame(1, "monitor", 1, 1002, true), ActionAllow, "cc-rtu-iec104-session"},
		{"step-position GI telemetry", "response", iFrame(5, "monitor", 1, 1301, true), ActionAllow, "cc-rtu-iec104-session"},
		{"monitor telemetry", "response", iFrame(13, "monitor", 1, 4001, true), ActionAllow, "cc-rtu-iec104-session"},
		{"timed single-point monitor telemetry", "response", iFrame(30, "monitor", 1, 1002, true), ActionAllow, "cc-rtu-iec104-session"},
		{"timed step-position telemetry", "response", iFrame(32, "monitor", 1, 1301, true), ActionAllow, "cc-rtu-iec104-session"},
		{"S-frame", "request", IEC104Context{APCIType: "S", Class: "system", SafeRead: true}, ActionAllow, "cc-rtu-iec104-session"},
		{"STOPDT act", "request", IEC104Context{APCIType: "U", Class: "system", SafeRead: true}, ActionAllow, "cc-rtu-iec104-session"},
		{"allowed breaker command", "request", iFrame(46, "control", 1, 2001, false), ActionAllow, "cc-rtu-breaker-command"},
		{"wrong CA", "request", iFrame(46, "control", 2, 2001, false), ActionDeny, "deny-other-iec104"},
		{"wrong IOA", "request", iFrame(46, "control", 1, 2002, false), ActionDeny, "deny-other-iec104"},
		{"wrong type", "request", iFrame(45, "control", 1, 2001, false), ActionDeny, "deny-other-iec104"},
		{"command confirmation", "response", iFrame(46, "control", 1, 2001, false), ActionAllow, "rtu-cc-command-confirm"},
		{"clock sync", "request", iFrame(103, "system", 1, 0, false), ActionDeny, "deny-other-iec104"},
		{"broadcast never allowed", "request", broadcastGI, ActionDeny, "deny-other-iec104"},
		{"CA 65535 is broadcast without the flag", "request", iFrame(100, "system", 65535, 0, true), ActionDeny, "deny-other-iec104"},
		{"malformed never allowed", "request", IEC104Context{APCIType: "I", TypeID: u8(46), Class: "control", Malformed: true, SafeRead: true}, ActionDeny, "deny-other-iec104"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			action, entry := ev.EvaluateIEC104(sessionCtx(tc.direction, tc.obj))
			if action != tc.want || entry == nil || entry.ID != tc.rule {
				id := "<nil>"
				if entry != nil {
					id = entry.ID
				}
				t.Fatalf("EvaluateIEC104 = %s by %s, want %s by %s", action, id, tc.want, tc.rule)
			}
		})
	}
}

func TestMonitorClassAndGIEnforcePolicy(t *testing.T) {
	evaluator := NewEvaluator(&Snapshot{Firewall: []Entry{
		iecEntry("monitor", ActionAllow, ICSPredicate{Classes: []string{"monitor"}, Direction: "response", Mode: "enforce"}),
		iecEntry("gi", ActionAllow, ICSPredicate{TypeIDs: []int{100}, ReadOnly: true, Mode: "enforce"}),
		iecEntry("deny-other", ActionDeny, ICSPredicate{Mode: "enforce"}),
	}})
	for _, typeID := range []uint8{1, 3, 5, 13, 30, 31, 32} {
		obj := iFrame(typeID, "monitor", 1, uint32(typeID), true)
		action, entry := evaluator.EvaluateIEC104(sessionCtx("response", obj))
		if action != ActionAllow || entry == nil || entry.ID != "monitor" {
			t.Errorf("monitor type %d = %s by %v, want monitor ALLOW", typeID, action, entry)
		}
	}
	for _, direction := range []string{"request", "response"} {
		gi := iFrame(100, "system", 1, 0, true)
		action, entry := evaluator.EvaluateIEC104(sessionCtx(direction, gi))
		if action != ActionAllow || entry == nil || entry.ID != "gi" {
			t.Errorf("GI %s = %s by %v, want GI ALLOW", direction, action, entry)
		}
	}
	unknown := IEC104Context{
		APCIType: "I", TypeID: u8(104), CA: u16(1), Class: "unknown", Unsupported: true,
	}
	if action, entry := evaluator.EvaluateIEC104(sessionCtx("response", unknown)); action != ActionDeny || entry == nil || entry.ID != "deny-other" {
		t.Errorf("unsupported type = %s by %v, want deny-other DENY", action, entry)
	}
}

func TestEvaluateIEC104NoMatchIsDeny(t *testing.T) {
	snap := euPolicy()
	snap.Firewall = snap.Firewall[:4] // drop the explicit deny; Default stays ALLOW
	ev := NewEvaluator(snap)
	if action, entry := ev.EvaluateIEC104(sessionCtx("request", iFrame(45, "control", 1, 2001, false))); action != ActionDeny || entry != nil {
		t.Fatalf("no match = %s, %v; want DENY, nil", action, entry)
	}
	// Another client is outside every IEC rule's tuple.
	ctx := sessionCtx("request", iFrame(100, "system", 1, 0, true))
	ctx.SrcIP = net.ParseIP("10.60.60.99")
	if action, entry := ev.EvaluateIEC104(ctx); action != ActionDeny || entry != nil {
		t.Fatalf("foreign client = %s, %v; want DENY, nil", action, entry)
	}
	if action, entry := ev.EvaluateIEC104(EvalContext{Proto: "tcp", Port: "2404"}); action != ActionDeny || entry != nil {
		t.Fatalf("missing IEC context = %s, %v; want DENY, nil", action, entry)
	}
	if action, entry := NewEvaluator(nil).EvaluateIEC104(sessionCtx("request", iFrame(100, "system", 1, 0, true))); action != ActionDeny || entry != nil {
		t.Fatalf("nil snapshot = %s, %v; want DENY, nil", action, entry)
	}
}

func TestEvaluateIEC104Predicates(t *testing.T) {
	cases := []struct {
		name  string
		pred  ICSPredicate
		obj   IEC104Context
		match bool
	}{
		{"typeIds without a type id", ICSPredicate{TypeIDs: []int{46}}, IEC104Context{APCIType: "S", Class: "system"}, false},
		{"ca without a ca", ICSPredicate{CA: []uint16{1}}, IEC104Context{APCIType: "U", Class: "system"}, false},
		{"ioa without an ioa", ICSPredicate{IOA: []IOARange{{Start: 0, End: 10}}}, IEC104Context{APCIType: "I", TypeID: u8(100), CA: u16(1)}, false},
		{"ioa 0 range edge", ICSPredicate{IOA: []IOARange{{Start: 0, End: 0}}}, iFrame(100, "system", 1, 0, true), true},
		{"ioa above 16 bits", ICSPredicate{IOA: []IOARange{{Start: 65536, End: 65567}}}, iFrame(46, "control", 1, 65567, false), true},
		{"ioa past range end", ICSPredicate{IOA: []IOARange{{Start: 65536, End: 65567}}}, iFrame(46, "control", 1, 65568, false), false},
		{"class list is OR", ICSPredicate{Classes: []string{"monitor", "system"}}, iFrame(100, "system", 1, 0, true), true},
		{"type 1 matches monitor class", ICSPredicate{Classes: []string{"monitor"}, ReadOnly: true}, iFrame(1, "monitor", 1, 1002, true), true},
		{"type 30 matches monitor class", ICSPredicate{Classes: []string{"monitor"}, ReadOnly: true}, iFrame(30, "monitor", 1, 1002, true), true},
		{"readOnly needs SafeRead", ICSPredicate{ReadOnly: true}, iFrame(101, "system", 1, 0, false), false},
		{"readOnly false is no constraint", ICSPredicate{}, iFrame(46, "control", 1, 1, false), true},
		{"unsupported type by class", ICSPredicate{Classes: []string{"unknown"}}, IEC104Context{APCIType: "I", TypeID: u8(104), CA: u16(1), Class: "unknown", Unsupported: true}, true},
		{"out-of-range type id never matches", ICSPredicate{TypeIDs: []int{300}}, iFrame(44, "unknown", 1, 1, false), false},
		{"writeOnly is invalid for iec104", ICSPredicate{WriteOnly: true}, iFrame(46, "control", 1, 1, false), false},
		{"generic fields are invalid for iec104", ICSPredicate{FunctionCode: []uint8{46}}, iFrame(46, "control", 1, 1, false), false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ev := NewEvaluator(&Snapshot{Firewall: []Entry{iecEntry("r", ActionDeny, tc.pred)}})
			_, entry := ev.EvaluateIEC104(sessionCtx("request", tc.obj))
			if got := entry != nil; got != tc.match {
				t.Fatalf("match = %v, want %v", got, tc.match)
			}
		})
	}
}

func TestIEC104Envelope(t *testing.T) {
	enforceRule := iecEntry("enforce", ActionAllow, ICSPredicate{TypeIDs: []int{46}, Mode: "enforce"})
	learnRule := iecEntry("learn", ActionAllow, ICSPredicate{ReadOnly: true, Mode: "learn"})
	inherit := iecEntry("inherit", ActionAllow, ICSPredicate{ReadOnly: true})
	l4 := Entry{ID: "l4", Protocols: []Protocol{{Name: "tcp", Port: "2404"}}, Action: ActionAllow}
	// The envelope ignores ASDU predicates: an L3/L4 session context has no
	// IEC104 object at all.
	session := sessionCtx("", IEC104Context{})
	session.ICS = nil

	cases := []struct {
		name     string
		rules    []Entry
		global   string
		ctx      EvalContext
		wantIn   bool
		wantMode string
	}{
		{"no IEC rules (milestone A, US)", []Entry{l4}, "enforce", session, false, ""},
		{"enforce rule", []Entry{l4, enforceRule}, "learn", session, true, "enforce"},
		{"rule learn beats global enforce", []Entry{learnRule}, "enforce", session, true, "learn"},
		{"blank rule mode inherits global", []Entry{inherit}, "Enforce", session, true, "enforce"},
		{"blank everywhere is learn", []Entry{inherit}, "", session, true, "learn"},
		{"any enforce match wins", []Entry{learnRule, enforceRule}, "learn", session, true, "enforce"},
		{"foreign client", []Entry{enforceRule}, "enforce", func() EvalContext {
			c := session
			c.SrcIP = net.ParseIP("10.60.60.99")
			return c
		}(), false, ""},
		{"other port", []Entry{enforceRule}, "enforce", func() EvalContext {
			c := session
			c.Port = "502"
			return c
		}(), false, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			in, mode := NewEvaluator(&Snapshot{Firewall: tc.rules}).IEC104Envelope(tc.ctx, tc.global)
			if in != tc.wantIn || mode != tc.wantMode {
				t.Fatalf("IEC104Envelope = %v, %q; want %v, %q", in, mode, tc.wantIn, tc.wantMode)
			}
		})
	}
}

// IEC104 entries take part in generic evaluation only through the IEC
// matcher: they never match US traffic and keep their ASDU predicates.
func TestGenericEvaluationOfIEC104Entries(t *testing.T) {
	snap := &Snapshot{
		Default:  ActionAllow,
		Firewall: []Entry{iecEntry("iec-deny-46", ActionDeny, ICSPredicate{TypeIDs: []int{46}})},
	}
	ev := NewEvaluator(snap)
	modbus := sessionCtx("request", IEC104Context{})
	modbus.ICS = &ICSContext{Protocol: "modbus", FunctionCode: 6, Direction: "request"}
	if got := ev.Evaluate(modbus); got != ActionAllow {
		t.Fatalf("modbus under an IEC rule = %s, want default ALLOW", got)
	}
	if got := ev.Evaluate(sessionCtx("request", iFrame(45, "control", 1, 1, false))); got != ActionAllow {
		t.Fatalf("type 45 under a typeIds [46] rule = %s, want default ALLOW", got)
	}
	if got := ev.Evaluate(sessionCtx("request", iFrame(46, "control", 1, 1, false))); got != ActionDeny {
		t.Fatalf("type 46 = %s, want DENY", got)
	}
	if !PreviewMatch(snap.Firewall[0], sessionCtx("request", iFrame(46, "control", 1, 1, false))) {
		t.Fatal("PreviewMatch must use the IEC matcher")
	}
}

func TestEffectiveMode(t *testing.T) {
	for _, tc := range []struct{ rule, global, want string }{
		{"enforce", "learn", "enforce"},
		{" Learn ", "enforce", "learn"},
		{"", "ENFORCE", "enforce"},
		{"", "", "learn"},
	} {
		if got := EffectiveMode(tc.rule, tc.global); got != tc.want {
			t.Fatalf("EffectiveMode(%q, %q) = %q, want %q", tc.rule, tc.global, got, tc.want)
		}
	}
}
