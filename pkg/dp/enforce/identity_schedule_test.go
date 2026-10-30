// SPDX-License-Identifier: Apache-2.0

package enforce

import (
	"bytes"
	"reflect"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/tonylturner/containd/pkg/dp/rules"
)

var maintenanceWindow = rules.SchedulePredicate{DaysOfWeek: []string{"Saturday", "Sunday"}, StartTime: "02:00", EndTime: "06:00", Timezone: "America/New_York"}

// goldenSnapshot is a maintenance-window policy with identities: a scheduled
// zone ALLOW, an identity ALLOW, a scheduled identity DENY, an unconditional
// ALLOW, a queued Modbus rule with an identity, and RESET, RATE_LIMIT and
// TAG rules with identities.
func goldenSnapshot() *rules.Snapshot {
	return &rules.Snapshot{
		Default:    rules.ActionDeny,
		ZoneIfaces: map[string][]string{"l3": {"eth3"}, "l1": {"eth1"}},
		IdentityBindings: []rules.IdentityBinding{
			{IP: "10.3.0.5", Identities: []string{"engineer"}},
			{IP: "10.3.0.9", Identities: []string{"contractor"}},
			{IP: "2001:db8::5", Identities: []string{"engineer"}},
		},
		Firewall: []rules.Entry{
			{ID: "maint-l3-to-l1", SourceZones: []string{"l3"}, DestZones: []string{"l1"}, Action: rules.ActionAllow, Schedule: maintenanceWindow},
			{ID: "eng-ssh", Identities: []string{"engineer"}, Protocols: []rules.Protocol{{Name: "tcp", Port: "22"}}, Action: rules.ActionAllow},
			{ID: "no-contractors", SourceZones: []string{"l3"}, Identities: []string{"contractor"}, Action: rules.ActionDeny, Schedule: maintenanceWindow},
			{ID: "web", Protocols: []rules.Protocol{{Name: "tcp", Port: "443"}}, Action: rules.ActionAllow},
			{ID: "modbus", Destinations: []string{"10.1.0.0/24"}, Protocols: []rules.Protocol{{Name: "tcp", Port: "502"}},
				ICS: rules.ICSPredicate{Mode: "enforce", Protocol: "modbus", FunctionCode: []uint8{3}}, Identities: []string{"engineer"}, Action: rules.ActionAllow},
			{ID: "reset-telnet", Identities: []string{"contractor"}, Protocols: []rules.Protocol{{Name: "tcp", Port: "23"}}, Action: rules.ActionReset, Schedule: maintenanceWindow},
			{ID: "snmp-meter", Identities: []string{"engineer"}, Protocols: []rules.Protocol{{Name: "udp", Port: "161"}},
				Action: rules.ActionRateLimit, RateLimit: &rules.RateLimit{PacketsPerSecond: 10}},
			{ID: "tag-engineers", Identities: []string{"engineer"}, Action: rules.ActionTag, Tag: "engineering"},
		},
	}
}

func goldenCompiler() *Compiler {
	c := NewCompiler()
	c.QueueID = 100
	c.ScheduleFrom = time.Date(2026, 10, 30, 12, 0, 0, 0, time.UTC)
	c.ScheduleHorizon = 72 * time.Hour
	return c
}

// TestScheduleSetsAgreeWithEvaluator samples every 5 minutes, and one
// second around every window boundary, over horizons that cross daylight
// saving changes: an ALLOW set holds exactly when the evaluator's window
// does, and a DENY set also holds outside the horizon.
func TestScheduleSetsAgreeWithEvaluator(t *testing.T) {
	for _, tc := range []struct {
		name  string
		sched rules.SchedulePredicate
		from  time.Time
	}{
		{"maintenance window, fall change", maintenanceWindow, time.Date(2026, 10, 29, 0, 0, 0, 0, time.UTC)},
		{"maintenance window, spring change", maintenanceWindow, time.Date(2026, 3, 5, 0, 0, 0, 0, time.UTC)},
		{"overnight in the spring gap", rules.SchedulePredicate{StartTime: "23:30", EndTime: "02:30", Timezone: "America/New_York"}, time.Date(2026, 3, 6, 0, 0, 0, 0, time.UTC)},
		{"overnight UTC weekdays", rules.SchedulePredicate{DaysOfWeek: []string{"Friday"}, StartTime: "22:00", EndTime: "04:00"}, time.Date(2026, 10, 29, 7, 13, 0, 0, time.UTC)},
		{"half-hour zone", rules.SchedulePredicate{StartTime: "09:00", EndTime: "17:30", Timezone: "Asia/Kolkata"}, time.Date(2026, 10, 26, 0, 0, 0, 0, time.UTC)},
		{"whole days", rules.SchedulePredicate{DaysOfWeek: []string{"Monday", "Tuesday"}}, time.Date(2026, 10, 25, 0, 0, 0, 0, time.UTC)},
	} {
		for _, deny := range []bool{false, true} {
			name := tc.name + "/allow"
			if deny {
				name = tc.name + "/deny"
			}
			t.Run(name, func(t *testing.T) {
				horizon := 6 * 24 * time.Hour
				to := tc.from.Add(horizon)
				elems, err := scheduleSet{sched: tc.sched, deny: deny}.elements(tc.from, to)
				if err != nil {
					t.Fatal(err)
				}
				intervals := parseIntervals(t, elems)
				// The grid is offset from every boundary: a closed nft
				// interval also holds the single nanosecond at its end
				// (TestScheduleSetEndInstant).
				samples := []time.Time{}
				for at := tc.from.Add(-time.Hour + time.Millisecond); at.Before(to.Add(time.Hour)); at = at.Add(5 * time.Minute) {
					samples = append(samples, at)
				}
				windows, err := tc.sched.Windows(tc.from.Add(-48*time.Hour), to.Add(48*time.Hour))
				if err != nil {
					t.Fatal(err)
				}
				for _, w := range windows {
					samples = append(samples, w.Start.Add(-time.Nanosecond), w.Start, w.End.Add(-time.Nanosecond), w.End.Add(time.Nanosecond))
				}
				for _, at := range samples {
					active, err := tc.sched.ActiveAt(at)
					if err != nil {
						t.Fatal(err)
					}
					inHorizon := !at.Before(tc.from) && at.Before(to)
					want := active && inHorizon
					if deny {
						want = active || !inHorizon
					}
					if got := intervals.contain(at); got != want {
						t.Fatalf("at %s: kernel set holds %v, want %v (active %v, in horizon %v)\nelements %v", at, got, want, active, inHorizon, elems)
					}
				}
			})
		}
	}
}

// TestScheduleSetEndInstant pins the one difference between a time set and
// the evaluator: nft intervals are closed, so a window's set element also
// holds the nanosecond at its end, which the evaluator excludes.
func TestScheduleSetEndInstant(t *testing.T) {
	from := time.Date(2026, 10, 30, 12, 0, 0, 0, time.UTC)
	elems, err := scheduleSet{sched: maintenanceWindow}.elements(from, from.Add(72*time.Hour))
	if err != nil || len(elems) == 0 {
		t.Fatalf("elements = %v, %v", elems, err)
	}
	end := time.Date(2026, 10, 31, 10, 0, 0, 0, time.UTC)
	if active, _ := maintenanceWindow.ActiveAt(end); active || !parseIntervals(t, elems).contain(end) {
		t.Fatalf("at the window end: evaluator %v, set %v; want false, true", active, parseIntervals(t, elems).contain(end))
	}
}

type interval struct{ lo, hi int64 } // closed, in nanoseconds

type intervals []interval

func (iv intervals) contain(at time.Time) bool {
	ns := at.UnixNano()
	for _, i := range iv {
		if ns >= i.lo && ns <= i.hi {
			return true
		}
	}
	return false
}

// parseIntervals reads nft "start-end" seconds elements as the kernel does:
// closed intervals in nanoseconds. Elements must be ordered and disjoint.
func parseIntervals(t *testing.T, elems []string) intervals {
	t.Helper()
	var out intervals
	for _, e := range elems {
		lo, hi, ok := strings.Cut(e, "-")
		a, errA := strconv.ParseInt(lo, 10, 64)
		b, errB := strconv.ParseInt(hi, 10, 64)
		if !ok || errA != nil || errB != nil || a > b {
			t.Fatalf("bad element %q", e)
		}
		i := interval{a * int64(time.Second), b * int64(time.Second)}
		if n := len(out); n > 0 && i.lo <= out[n-1].hi {
			t.Fatalf("elements %v overlap: nft refuses them", elems)
		}
		out = append(out, i)
	}
	return out
}

// TestScheduleHorizonExhaustion: past its horizon a scheduled ALLOW set is
// empty and a scheduled DENY set holds all time.
func TestScheduleHorizonExhaustion(t *testing.T) {
	from := time.Date(2026, 10, 30, 12, 0, 0, 0, time.UTC)
	to := from.Add(time.Hour)
	allow, err := scheduleSet{sched: maintenanceWindow}.elements(from, to)
	if err != nil || len(allow) != 0 {
		t.Fatalf("ALLOW elements without a window in the horizon = %v, %v; want none", allow, err)
	}
	deny, err := scheduleSet{sched: maintenanceWindow, deny: true}.elements(from, to)
	if err != nil {
		t.Fatal(err)
	}
	if want := []string{"0-1793361600", "1793365200-9223372036"}; !reflect.DeepEqual(deny, want) {
		t.Fatalf("DENY elements = %v, want %v", deny, want)
	}
}

// TestIdentityLowering covers address families, unbound identities and
// queued rules.
func TestIdentityLowering(t *testing.T) {
	snap := &rules.Snapshot{
		Default: rules.ActionAllow,
		IdentityBindings: []rules.IdentityBinding{
			{IP: "10.0.0.5", Identities: []string{"ops"}},
			{IP: "2001:db8::6", Identities: []string{"ops", "v6only"}},
		},
		Firewall: []rules.Entry{
			{ID: "a-cidr", Identities: []string{"ops"}, Sources: []string{"10.0.0.0/24"}, Action: rules.ActionAllow},
			{ID: "b-unbound-allow", Identities: []string{"nobody"}, Action: rules.ActionAllow},
			{ID: "c-unbound-deny", Identities: []string{"nobody"}, Action: rules.ActionDeny},
			{ID: "d-v6only-cidr", Identities: []string{"v6only"}, Destinations: []string{"10.9.0.0/16"}, Action: rules.ActionDeny},
			{ID: "e-both", Identities: []string{"ops", "ops"}, Protocols: []rules.Protocol{{Name: "udp", Port: "161"}}, Action: rules.ActionDeny},
		},
	}
	out, err := compileWithoutCounters(NewCompiler(), snap)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"set identity4_6f7073 {\n    type ipv4_addr;\n    elements = { 10.0.0.5 }\n  }",
		"set identity6_6f7073 {\n    type ipv6_addr;\n    elements = { 2001:db8::6 }\n  }",
		"    ip saddr @identity4_6f7073 ip saddr { 10.0.0.0/24 } accept;\n",
		"    ip saddr @identity4_6f7073 udp dport 161 drop;\n    ip6 saddr @identity6_6f7073 udp dport 161 drop;\n",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("missing %q:\n%s", want, out)
		}
	}
	for _, unwanted := range []string{"ip6 saddr @identity6_6f7073 ip saddr", "6e6f626f6479", "identity6_76366f6e6c79"} {
		if strings.Contains(out, unwanted) {
			t.Fatalf("unexpected %q:\n%s", unwanted, out)
		}
	}
	var got []string
	for _, w := range NewCompiler().RuleWarnings(snap) {
		got = append(got, w.RuleID)
	}
	if want := []string{"b-unbound-allow", "c-unbound-deny", "d-v6only-cidr"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("warnings for %v, want %v", got, want)
	}
	assertDeclaredSets(t, out)
}

// TestPredicatesOnlyWhereNftablesDecides: without a queue an ICS rule is
// decided by nftables and guarded. With one it keeps its unguarded queue
// line, and the engine decides the predicates of the client's messages; the
// kernel rechecks the rest of its connections against them, while a queued
// DENY or an unconditional queued ALLOW leaves its connections to the
// engine.
func TestPredicatesOnlyWhereNftablesDecides(t *testing.T) {
	entry := rules.Entry{ID: "modbus", Protocols: []rules.Protocol{{Name: "tcp", Port: "502"}},
		ICS: rules.ICSPredicate{Mode: "enforce", Protocol: "modbus"}, Identities: []string{"ops"}, Action: rules.ActionAllow, Schedule: maintenanceWindow}
	snap := &rules.Snapshot{Firewall: []rules.Entry{entry}, IdentityBindings: []rules.IdentityBinding{{IP: "10.0.0.5", Identities: []string{"ops"}}}}
	c := goldenCompiler()
	queued, err := compileWithoutCounters(c, snap)
	if err != nil {
		t.Fatal(err)
	}
	set := "@schedule_allow_41_0120_0360_416d65726963612f4e65775f596f726b"
	for _, want := range []string{
		"    meta mark & 0x04000000 == 0 tcp dport 502 jump ics_queue;\n    ct state established jump conditional_scope;\n",
		"  chain conditional_scope {\n    meta l4proto tcp ct reply proto-src 502 goto conditional_policy;\n  }\n",
		"    ct status dnat return;\n    meta l4proto tcp ct reply proto-src 502 ct original ip saddr @identity4_6f7073 meta time " + set + " return;\n    drop;\n",
	} {
		if !strings.Contains(queued, want) {
			t.Fatalf("missing %q:\n%s", want, queued)
		}
	}
	for _, a := range []rules.Action{rules.ActionDeny, rules.ActionAllow} {
		other := entry
		other.Action = a
		if a == rules.ActionAllow {
			other.Identities, other.Schedule = nil, rules.SchedulePredicate{}
		}
		text, err := compileWithoutCounters(c, &rules.Snapshot{Firewall: []rules.Entry{other}, IdentityBindings: snap.IdentityBindings})
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(text, "    meta mark & 0x04000000 == 0 tcp dport 502 jump ics_queue;\n") || strings.Contains(text, "identity4_") ||
			strings.Contains(text, "schedule_") || strings.Contains(text, conditionalScopeChain) {
			t.Fatalf("queued %s rule was guarded:\n%s", a, text)
		}
	}
	c.QueueID = 0
	plain, err := compileWithoutCounters(c, snap)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"    ip saddr @identity4_6f7073 meta time " + set + " tcp dport 502 accept;\n",
		"    ct state established jump conditional_scope;\n    ct state { established, related } accept;\n",
	} {
		if !strings.Contains(plain, want) {
			t.Fatalf("missing %q:\n%s", want, plain)
		}
	}
}

// TestRecheckVerdicts covers the policy chain's verdicts: a RESET rejects
// per protocol, and an ALLOW default returns.
func TestRecheckVerdicts(t *testing.T) {
	snap := &rules.Snapshot{
		Default: rules.ActionAllow,
		Firewall: []rules.Entry{
			{ID: "reset-any", Action: rules.ActionReset, Schedule: maintenanceWindow},
			{ID: "reset-udp", Protocols: []rules.Protocol{{Name: "udp", Port: "53"}}, Action: rules.ActionReset},
		},
	}
	p, err := newPredicates(snap, 0)
	if err != nil {
		t.Fatal(err)
	}
	var b bytes.Buffer
	if err := p.writeRecheckChains(&b, targetForward); err != nil {
		t.Fatal(err)
	}
	set := "@schedule_deny_41_0120_0360_416d65726963612f4e65775f596f726b"
	want := "  chain conditional_scope {\n    goto conditional_policy;\n  }\n" +
		"  chain conditional_policy {\n    ct status dnat return;\n" +
		"    meta time " + set + " meta l4proto tcp reject with tcp reset;\n" +
		"    meta time " + set + " reject with icmpx admin-prohibited;\n" +
		"    meta l4proto udp ct reply proto-src 53 reject with icmpx admin-prohibited;\n" +
		"    return;\n  }\n"
	if b.String() != want {
		t.Fatalf("recheck chains:\n%s\nwant:\n%s", b.String(), want)
	}
}

// TestScheduleRefresh refills each time set in one transaction.
func TestScheduleRefresh(t *testing.T) {
	c := goldenCompiler()
	c.ScheduleFrom = c.ScheduleFrom.Add(24 * time.Hour)
	script, err := c.ScheduleRefresh(goldenSnapshot())
	if err != nil {
		t.Fatal(err)
	}
	want := "flush set inet containd_policy schedule_allow_41_0120_0360_416d65726963612f4e65775f596f726b\n" +
		"add element inet containd_policy schedule_allow_41_0120_0360_416d65726963612f4e65775f596f726b { 1793516400-1793530800 }\n" +
		"flush set inet containd_policy schedule_deny_41_0120_0360_416d65726963612f4e65775f596f726b\n" +
		"add element inet containd_policy schedule_deny_41_0120_0360_416d65726963612f4e65775f596f726b { 0-1793448000, 1793516400-1793530800, 1793707200-9223372036 }\n"
	if script != want {
		t.Fatalf("refresh:\n%s\nwant:\n%s", script, want)
	}
	if script, err := c.ScheduleRefresh(&rules.Snapshot{}); err != nil || script != "" {
		t.Fatalf("refresh without schedules = %q, %v", script, err)
	}
}

var elementsRE = regexp.MustCompile(`elements = \{ ([^}]*) \}`)

// TestTemplatesCompileToTimeSets: every interval written is ordered and
// disjoint, as nft requires, for the shipped maintenance template windows
// over a year of horizons.
func TestTemplatesCompileToTimeSets(t *testing.T) {
	for day := 0; day < 366; day += 3 {
		c := NewCompiler()
		c.ScheduleFrom = time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC).AddDate(0, 0, day)
		c.ScheduleHorizon = 7 * 24 * time.Hour
		out, err := c.CompileFirewall(goldenSnapshot())
		if err != nil {
			t.Fatal(err)
		}
		for _, m := range elementsRE.FindAllStringSubmatch(out, -1) {
			if strings.Contains(m[1], "-") && !strings.Contains(m[1], ":") {
				parseIntervals(t, strings.Split(m[1], ", "))
			}
		}
	}
}

// TestPredicatesOnEveryAction: RESET, RATE_LIMIT and TAG lines carry the
// rule's identity and schedule clauses like ALLOW and DENY lines. A meter
// line for tracked packets matches the opener from conntrack, since it
// meters both directions, one for untracked packets the sender as an
// opener; each takes only its address family's identity sets, and an
// identity nothing binds leaves no line, whatever the action.
func TestPredicatesOnEveryAction(t *testing.T) {
	bindings := []rules.IdentityBinding{{IP: "10.0.0.5", Identities: []string{"ops"}}, {IP: "2001:db8::6", Identities: []string{"ops"}}}
	ops := "ip saddr @identity4_6f7073"
	ops6 := "ip6 saddr @identity6_6f7073"
	set := "meta time @schedule_deny_40_0120_0360_555443"
	window := rules.SchedulePredicate{DaysOfWeek: []string{"Saturday"}, StartTime: "02:00", EndTime: "06:00"}
	for _, tc := range []struct {
		name  string
		entry rules.Entry
		want  []string
	}{
		{"reset", rules.Entry{ID: "r", Action: rules.ActionReset, Identities: []string{"ops"}, Schedule: window,
			Protocols: []rules.Protocol{{Name: "tcp", Port: "23"}}},
			[]string{ops + " " + set + " tcp dport 23 reject with tcp reset", ops6 + " " + set + " tcp dport 23 reject with tcp reset"}},
		{"tag", rules.Entry{ID: "t", Action: rules.ActionTag, Tag: "ops", Identities: []string{"ops"},
			Protocols: []rules.Protocol{{Name: "tcp", Port: "23"}}},
			[]string{ops + " tcp dport 23", ops6 + " tcp dport 23"}},
		{"rate limit", rules.Entry{ID: "m", Action: rules.ActionRateLimit, RateLimit: &rules.RateLimit{PacketsPerSecond: 10},
			Identities: []string{"ops"}, Protocols: []rules.Protocol{{Name: "udp", Port: "161"}}},
			[]string{
				ops + " meta nfproto ipv4 " + untrackedState + " udp dport 161",
				"ct original " + ops + " meta nfproto ipv4 " + trackedState + " meta l4proto udp ct reply proto-src 161",
				ops6 + " meta nfproto ipv6 " + untrackedState + " udp dport 161",
				"ct original " + ops6 + " meta nfproto ipv6 " + trackedState + " meta l4proto udp ct reply proto-src 161",
			}},
		{"unbound tag", rules.Entry{ID: "u", Action: rules.ActionTag, Tag: "x", Identities: []string{"nobody"}}, nil},
		{"unbound rate limit", rules.Entry{ID: "v", Action: rules.ActionRateLimit, RateLimit: &rules.RateLimit{PacketsPerSecond: 10},
			Identities: []string{"nobody"}}, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p, err := newPredicates(&rules.Snapshot{IdentityBindings: bindings, Firewall: []rules.Entry{tc.entry}}, 0)
			if err != nil {
				t.Fatal(err)
			}
			lines, err := guardedWithoutCounters(p, tc.entry)
			if err != nil {
				t.Fatal(err)
			}
			if len(lines) != len(tc.want) {
				t.Fatalf("lines = %q, want prefixes %q", lines, tc.want)
			}
			for i, want := range tc.want {
				if !strings.HasPrefix(lines[i], want) {
					t.Fatalf("line %d = %q, want prefix %q", i, lines[i], want)
				}
			}
		})
	}
}
