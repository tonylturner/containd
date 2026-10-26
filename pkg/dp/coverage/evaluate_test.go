// SPDX-License-Identifier: Apache-2.0

package coverage

import (
	"reflect"
	"testing"

	"github.com/tonylturner/containd/pkg/dp/rules"
)

func inline() Settings {
	return Settings{Enforcement: true, QueueID: 101, DPIEnabled: true, DPIMode: "enforce"}
}

func modbusRule(id, mode string) rules.Entry {
	return rules.Entry{
		ID: id, Sources: []string{"10.0.0.5/32"}, Destinations: []string{"10.1.0.4/32"},
		Protocols: []rules.Protocol{{Name: "tcp", Port: "502"}},
		ICS:       rules.ICSPredicate{Protocol: "modbus", FunctionCode: []uint8{3}, Mode: mode},
		Action:    rules.ActionAllow,
	}
}

func codes(r Rule) []Code {
	var out []Code
	for _, x := range r.Reasons {
		out = append(out, x.Code)
	}
	return out
}

func TestEvaluate(t *testing.T) {
	iec := modbusRule("iec", "")
	iec.ICS = rules.ICSPredicate{Protocol: "iec104"}
	cases := []struct {
		name   string
		entry  rules.Entry
		mutate func(*Settings)
		mode   string
		state  State
		codes  []Code
	}{
		{"inline enforce", modbusRule("r", ""), nil, "enforce", Enforcing, nil},
		{"explicit learn", modbusRule("r", "learn"), nil, "learn", Monitoring, nil},
		{"global learn inherited", modbusRule("r", ""), func(s *Settings) { s.DPIMode = "learn" }, "learn", Monitoring, nil},
		{"no global mode defaults to learn", modbusRule("r", ""), func(s *Settings) { s.DPIMode = "" }, "learn", Monitoring, nil},
		{"rule enforce over global learn", modbusRule("r", "enforce"), func(s *Settings) { s.DPIMode = "learn" }, "enforce", Enforcing, nil},
		{"no queue", modbusRule("r", ""), func(s *Settings) { s.QueueID = 0 }, "enforce", NotEnforcing, []Code{NoInlinePath}},
		{"no queue in learn is not a fault", modbusRule("r", "learn"), func(s *Settings) { s.QueueID = 0 }, "learn", Monitoring, nil},
		{"nft enforcement off", modbusRule("r", ""), func(s *Settings) { s.Enforcement = false }, "enforce", NotEnforcing, []Code{EnforcementDisabled}},
		{"dpi off", modbusRule("r", ""), func(s *Settings) { s.DPIEnabled = false }, "enforce", NotEnforcing, []Code{DPIDisabled}},
		{"dpi off in learn explains the gap", modbusRule("r", "learn"), func(s *Settings) { s.DPIEnabled = false }, "learn", Monitoring, []Code{DPIDisabled}},
		{"decoder off", modbusRule("r", ""), func(s *Settings) { s.ICSProtocols = map[string]bool{"modbus": false} }, "enforce", NotEnforcing, []Code{DecoderDisabled}},
		{"absent decoder key is enabled", modbusRule("r", ""), func(s *Settings) { s.ICSProtocols = map[string]bool{"dnp3": false} }, "enforce", Enforcing, nil},
		{"ip exclusion on the server", modbusRule("r", ""), func(s *Settings) {
			s.Exclusions = []Exclusion{{Value: "10.1.0.4", Type: "ip"}}
		}, "enforce", Partial, []Code{ExclusionOverlap}},
		{"cidr exclusion around the client", modbusRule("r", ""), func(s *Settings) {
			s.Exclusions = []Exclusion{{Value: "10.0.0.0/8", Type: "cidr"}}
		}, "enforce", Partial, []Code{ExclusionOverlap}},
		{"unrelated exclusion", modbusRule("r", ""), func(s *Settings) {
			s.Exclusions = []Exclusion{{Value: "192.0.2.1", Type: "ip"}, {Value: "198.51.100.0/24", Type: "cidr"}}
		}, "enforce", Enforcing, nil},
		{"domain exclusion", modbusRule("r", ""), func(s *Settings) {
			s.Exclusions = []Exclusion{{Value: "*.example.com", Type: "domain"}}
		}, "enforce", Partial, []Code{DomainExclusion}},
		{"no-inline-path outranks an exclusion", modbusRule("r", ""), func(s *Settings) {
			s.QueueID = 0
			s.Exclusions = []Exclusion{{Value: "*.example.com", Type: "domain"}}
		}, "enforce", NotEnforcing, []Code{NoInlinePath, DomainExclusion}},
		{"every cause listed", modbusRule("r", ""), func(s *Settings) {
			*s = Settings{DPIMode: "enforce", ICSProtocols: map[string]bool{"modbus": false}}
		}, "enforce", NotEnforcing, []Code{EnforcementDisabled, NoInlinePath, DPIDisabled, DecoderDisabled}},
		{"iec104 ignores exclusions and the DPI master switch", iec, func(s *Settings) {
			s.DPIEnabled = false
			s.Exclusions = []Exclusion{{Value: "10.1.0.4", Type: "ip"}, {Value: "*.example.com", Type: "domain"}}
		}, "enforce", Enforcing, nil},
		{"iec104 decoder off", iec, func(s *Settings) { s.ICSProtocols = map[string]bool{"iec104": false} }, "enforce", NotEnforcing, []Code{DecoderDisabled}},
		{"iec104 without queue", iec, func(s *Settings) { s.QueueID = 0 }, "enforce", NotEnforcing, []Code{NoInlinePath}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s := inline()
			if tc.mutate != nil {
				tc.mutate(&s)
			}
			got := Evaluate(&rules.Snapshot{Firewall: []rules.Entry{tc.entry}}, s)
			if len(got) != 1 {
				t.Fatalf("got %d rules, want 1", len(got))
			}
			r := got[0]
			if r.RuleID != tc.entry.ID || r.Protocol != tc.entry.ICS.Protocol || r.Mode != tc.mode || r.State != tc.state {
				t.Fatalf("got %+v, want mode %s state %s", r, tc.mode, tc.state)
			}
			if !reflect.DeepEqual(codes(r), tc.codes) {
				t.Fatalf("codes = %v, want %v", codes(r), tc.codes)
			}
			for _, x := range r.Reasons {
				if x.Message == "" || x.Matches != 0 {
					t.Fatalf("reason %+v: want a message and no runtime matches", x)
				}
				if (x.Code == ExclusionOverlap || x.Code == DomainExclusion) && x.Value == "" {
					t.Fatalf("exclusion reason %+v names no exclusion", x)
				}
			}
		})
	}
}

func TestEvaluateSkipsRulesWithoutProtocolAndSortsByID(t *testing.T) {
	l4 := modbusRule("a-l4", "enforce")
	l4.ICS = rules.ICSPredicate{Mode: "enforce"}
	snap := &rules.Snapshot{Firewall: []rules.Entry{modbusRule("z", ""), l4, modbusRule("m", "learn")}}
	got := Evaluate(snap, inline())
	if len(got) != 2 || got[0].RuleID != "m" || got[1].RuleID != "z" {
		t.Fatalf("got %+v, want rules m then z", got)
	}
	if Evaluate(nil, inline()) != nil || Evaluate(&rules.Snapshot{}, inline()) != nil {
		t.Fatal("no semantic rule must give no coverage")
	}
}

func TestExclusionOverlaps(t *testing.T) {
	cases := []struct {
		name     string
		x        Exclusion
		src, dst []string
		want     bool
	}{
		{"ip on destination", Exclusion{"10.1.0.4", "ip"}, []string{"10.0.0.5/32"}, []string{"10.1.0.4/32"}, true},
		{"cidr meets a wider source", Exclusion{"10.0.0.128/25", "cidr"}, []string{"10.0.0.0/24"}, []string{"10.1.0.4/32"}, true},
		{"disjoint", Exclusion{"192.0.2.0/24", "cidr"}, []string{"10.0.0.5/32"}, []string{"10.1.0.4/32"}, false},
		{"empty side is any address", Exclusion{"192.0.2.1", "ip"}, nil, []string{"10.1.0.4/32"}, true},
		{"vpn token counts as overlapping", Exclusion{"192.0.2.1", "ip"}, []string{"vpn:any"}, []string{"10.1.0.4/32"}, true},
		{"bare address side", Exclusion{"10.1.0.4", "ip"}, []string{"10.0.0.5"}, []string{"10.1.0.4"}, true},
		{"domain never overlaps", Exclusion{"example.com", "domain"}, nil, nil, false},
		{"unparseable exclusion never overlaps", Exclusion{"nope", "ip"}, nil, nil, false},
	}
	for _, tc := range cases {
		if got := ExclusionOverlaps(tc.x, tc.src, tc.dst); got != tc.want {
			t.Errorf("%s: got %v, want %v", tc.name, got, tc.want)
		}
	}
}

func TestSummarize(t *testing.T) {
	r := func(s State) Rule { return Rule{State: s} }
	cases := []struct {
		name string
		in   []Rule
		want Summary
	}{
		{"none", nil, Summary{State: SummaryNone}},
		{"monitoring only", []Rule{r(Monitoring)}, Summary{State: "monitoring", Monitoring: 1}},
		{"enforcing beats monitoring", []Rule{r(Monitoring), r(Enforcing)}, Summary{State: "enforcing", Enforcing: 1, Monitoring: 1}},
		{"partial is worse", []Rule{r(Enforcing), r(Partial)}, Summary{State: "partial", Enforcing: 1, Partial: 1}},
		{"not enforcing is worst", []Rule{r(Partial), r(NotEnforcing), r(Enforcing)},
			Summary{State: "not_enforcing", Enforcing: 1, Partial: 1, NotEnforcing: 1}},
	}
	for _, tc := range cases {
		if got := Summarize(tc.in); got != tc.want {
			t.Errorf("%s: got %+v, want %+v", tc.name, got, tc.want)
		}
	}
}
