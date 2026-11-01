// SPDX-License-Identifier: Apache-2.0

package rules

import (
	"net"
	"reflect"
	"testing"
)

func l4Ctx(src, dst, proto, port string) EvalContext {
	return EvalContext{SrcIP: net.ParseIP(src), DstIP: net.ParseIP(dst), Proto: proto, Port: port}
}

func tcpEntry(id string, action Action, port string) Entry {
	return Entry{ID: id, Protocols: []Protocol{{Name: "tcp", Port: port}}, Action: action}
}

// The configured terminal order decides; effects never decide.
func TestEvaluateMatchPrecedence(t *testing.T) {
	plc := tcpEntry("z-allow-plc", ActionAllow, "502")
	plc.Sources = []string{"10.0.0.5/32"}
	police := tcpEntry("rl-502", ActionRateLimit, "502")
	police.RateLimit = &RateLimit{PacketsPerSecond: 10, Burst: 10}
	label := Entry{ID: "tag-all", Action: ActionTag, Tag: "seen"}
	snap := &Snapshot{Default: ActionDeny, Firewall: []Entry{
		tcpEntry("a-deny-502", ActionDeny, "502"),
		police,
		label,
		plc,
		tcpEntry("m-reset-telnet", ActionReset, "23"),
		tcpEntry("b-deny-telnet", ActionDeny, "23"),
		tcpEntry("b-deny-ssh", ActionDeny, "22"),
		tcpEntry("a-reset-ssh", ActionReset, "22"),
		tcpEntry("y-allow-ssh-admin", ActionAllow, "22"),
	}}
	snap.Firewall[8].Sources = []string{"10.0.0.9/32"}
	ev := NewEvaluator(snap)
	for _, tc := range []struct {
		name   string
		ctx    EvalContext
		action Action
		rule   string
	}{
		{"earlier broader DENY wins", l4Ctx("10.0.0.5", "10.0.1.1", "tcp", "502"), ActionDeny, "a-deny-502"},
		{"DENY when no ALLOW matches; RATE_LIMIT does not decide", l4Ctx("10.0.0.6", "10.0.1.1", "tcp", "502"), ActionDeny, "a-deny-502"},
		{"RESET listed before DENY", l4Ctx("10.0.0.6", "10.0.1.1", "tcp", "23"), ActionReset, "m-reset-telnet"},
		{"DENY listed before RESET", l4Ctx("10.0.0.6", "10.0.1.1", "tcp", "22"), ActionDeny, "b-deny-ssh"},
		{"earlier DENY beats ALLOW", l4Ctx("10.0.0.9", "10.0.1.1", "tcp", "22"), ActionDeny, "b-deny-ssh"},
		{"TAG does not admit: default", l4Ctx("10.0.0.6", "10.0.1.1", "tcp", "80"), ActionDeny, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			action, entry := ev.EvaluateMatch(tc.ctx)
			if got := ruleID(entry); action != tc.action || got != tc.rule {
				t.Fatalf("EvaluateMatch = %s by %q, want %s by %q", action, got, tc.action, tc.rule)
			}
		})
	}
	snap.Default = ActionAllow
	if action, entry := NewEvaluator(snap).EvaluateMatch(l4Ctx("10.0.0.6", "10.0.1.1", "tcp", "80")); action != ActionAllow || entry != nil {
		t.Fatalf("ALLOW default = %s by %q", action, ruleID(entry))
	}
}

func TestEffectsAloneAdmitNothing(t *testing.T) {
	police := Entry{ID: "rl", Action: ActionRateLimit, RateLimit: &RateLimit{PacketsPerSecond: 1}}
	snap := &Snapshot{Default: ActionDeny, Firewall: []Entry{police, {ID: "tag", Action: ActionTag, Tag: "x"}}}
	ev := NewEvaluator(snap)
	if action, entry := ev.EvaluateMatch(l4Ctx("10.0.0.1", "10.0.0.2", "udp", "53")); action != ActionDeny || entry != nil {
		t.Fatalf("effects only = %s by %q, want the DENY default", action, ruleID(entry))
	}
	if got := ev.AnyMatch(l4Ctx("10.0.0.1", "10.0.0.2", "udp", "53")); got == nil || got.ID != "rl" {
		t.Fatalf("AnyMatch = %q, want the first entry of any action", ruleID(got))
	}
}

// An earlier enforcing ICS DENY beats a later broad plain ALLOW.
func TestGenericICSDenyBeforeAllow(t *testing.T) {
	write := Entry{ID: "a-deny-write", Protocols: []Protocol{{Name: "tcp", Port: "502"}}, Action: ActionDeny,
		ICS: ICSPredicate{Protocol: "modbus", FunctionCode: []uint8{6}, Mode: "enforce"}}
	ev := NewEvaluator(&Snapshot{Default: ActionDeny, Firewall: []Entry{write, tcpEntry("z-allow-502", ActionAllow, "502")}})
	ctx := l4Ctx("10.0.0.1", "10.0.0.2", "tcp", "502")
	ctx.ICS = &ICSContext{Protocol: "modbus", HasFunctionCode: true, FunctionCode: 6}
	if action, entry := ev.EvaluateMatch(ctx); action != ActionDeny || ruleID(entry) != "a-deny-write" {
		t.Fatalf("FC6 = %s by %q, want DENY by a-deny-write", action, ruleID(entry))
	}
}

// IEC104 objects follow the same precedence among IEC104 rules; a broad
// L4 ALLOW still takes no part.
func TestEvaluateIEC104Precedence(t *testing.T) {
	snap := &Snapshot{Default: ActionAllow, Firewall: []Entry{
		{ID: "0-l4-any-2404", Protocols: []Protocol{{Name: "tcp", Port: "2404"}}, Action: ActionAllow},
		iecEntry("b-deny-iec", ActionDeny, ICSPredicate{Mode: "enforce"}),
		iecEntry("a-deny-control", ActionDeny, ICSPredicate{Classes: []string{"control"}, Mode: "enforce"}),
		iecEntry("z-allow-gi", ActionAllow, ICSPredicate{TypeIDs: []int{100}, Direction: "request", Mode: "enforce"}),
	}}
	ev := NewEvaluator(snap)
	for _, tc := range []struct {
		name   string
		obj    IEC104Context
		action Action
		rule   string
	}{
		{"earlier DENY beats later ALLOW", iFrame(100, "system", 1, 0, true), ActionDeny, "b-deny-iec"},
		{"first DENY by position", iFrame(46, "control", 1, 2001, false), ActionDeny, "b-deny-iec"},
		{"other DENY", iFrame(103, "system", 1, 0, false), ActionDeny, "b-deny-iec"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			action, entry := ev.EvaluateIEC104(sessionCtx("request", tc.obj))
			if got := ruleID(entry); action != tc.action || got != tc.rule {
				t.Fatalf("EvaluateIEC104 = %s by %q, want %s by %q", action, got, tc.action, tc.rule)
			}
		})
	}
}

func TestDecisionOrder(t *testing.T) {
	entries := []Entry{
		{ID: "d2", Action: ActionDeny}, {ID: "t", Action: ActionTag}, {ID: "a2", Action: ActionAllow},
		{ID: "r1", Action: ActionReset}, {ID: "rl", Action: ActionRateLimit}, {ID: "a1", Action: ActionAllow}, {ID: "d1", Action: ActionDeny},
	}
	var got []string
	for _, i := range DecisionOrder(entries) {
		got = append(got, entries[i].ID)
	}
	if want := []string{"a1", "a2", "d1", "d2", "r1"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("DecisionOrder = %v, want %v", got, want)
	}
}

func TestTags(t *testing.T) {
	snap := &Snapshot{Firewall: []Entry{
		{ID: "plc", Sources: []string{"10.0.0.0/24"}, Protocols: []Protocol{{Name: "tcp", Port: "502"}}, Action: ActionTag, Tag: "plc"},
		{ID: "plc-again", Destinations: []string{"10.0.1.0/24"}, Action: ActionTag, Tag: "plc"},
		{ID: "ot", DestZones: []string{"ot"}, Action: ActionTag, Tag: "ot"},
		{ID: "guests", Identities: []string{"guest"}, Action: ActionTag, Tag: "guest"},
		tcpEntry("allow", ActionAllow, "502"),
	}}
	ev := NewEvaluator(snap)
	if !ev.HasTags() || !ev.TagsUseZones() {
		t.Fatalf("HasTags=%t TagsUseZones=%t", ev.HasTags(), ev.TagsUseZones())
	}
	ctx := l4Ctx("10.0.0.5", "10.0.1.1", "tcp", "502")
	ctx.DstZone = "ot"
	if got, want := ev.Tags(ctx), []string{"ot", "plc"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("Tags = %v, want %v", got, want)
	}
	if got := ev.Tags(l4Ctx("192.0.2.1", "192.0.2.2", "udp", "53")); got != nil {
		t.Fatalf("Tags of an unmatched tuple = %v", got)
	}
	if ev := NewEvaluator(&Snapshot{Firewall: []Entry{tcpEntry("allow", ActionAllow, "1")}}); ev.HasTags() || ev.TagsUseZones() {
		t.Fatal("a snapshot without TAG rules has tags")
	}
}

func ruleID(e *Entry) string {
	if e == nil {
		return ""
	}
	return e.ID
}
