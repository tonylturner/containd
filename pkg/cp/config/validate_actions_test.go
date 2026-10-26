// SPDX-License-Identifier: Apache-2.0

package config

import (
	"encoding/json"
	"fmt"
	"reflect"
	"strings"
	"testing"
)

func actionRule(mut func(*Rule)) Rule {
	r := Rule{ID: "r1", Protocols: []Protocol{{Name: "tcp", Port: "23"}}, Action: ActionReset}
	mut(&r)
	return r
}

func TestValidateRuleActions(t *testing.T) {
	rate := func(pps, burst uint32) *RateLimitConfig { return &RateLimitConfig{PacketsPerSecond: pps, Burst: burst} }
	for _, tc := range []struct {
		name string
		rule Rule
		err  string // "" means valid
	}{
		{"RESET", actionRule(func(*Rule) {}), ""},
		{"RESET with an ics protocol", actionRule(func(r *Rule) { r.ICS = ICSPredicate{Protocol: "modbus"} }), "cannot take an ics protocol"},
		{"RESET with iec104", actionRule(func(r *Rule) { r.ICS = ICSPredicate{Protocol: ICSProtocolIEC104} }), "cannot take an ics protocol"},
		{"RESET with an ics mode only", actionRule(func(r *Rule) { r.ICS = ICSPredicate{Mode: "enforce"} }), ""},
		{"RESET with rateLimit", actionRule(func(r *Rule) { r.RateLimit = rate(1, 0) }), "rateLimit is only valid with action RATE_LIMIT"},
		{"lower-case action", actionRule(func(r *Rule) { r.Action = "reset" }), "invalid action"},
		{"REJECT", actionRule(func(r *Rule) { r.Action = "REJECT" }), "invalid action"},
		{"RATE_LIMIT", actionRule(func(r *Rule) { r.Action, r.RateLimit = ActionRateLimit, rate(1, 0) }), ""},
		{"RATE_LIMIT at its bounds", actionRule(func(r *Rule) { r.Action, r.RateLimit = ActionRateLimit, rate(1_000_000, 1_000_000) }), ""},
		{"RATE_LIMIT without rateLimit", actionRule(func(r *Rule) { r.Action = ActionRateLimit }), "needs rateLimit"},
		{"RATE_LIMIT at zero", actionRule(func(r *Rule) { r.Action, r.RateLimit = ActionRateLimit, rate(0, 5) }), "packetsPerSecond 0 is out of range 1-1000000"},
		{"RATE_LIMIT too fast", actionRule(func(r *Rule) { r.Action, r.RateLimit = ActionRateLimit, rate(1_000_001, 0) }), "out of range"},
		{"RATE_LIMIT burst too deep", actionRule(func(r *Rule) { r.Action, r.RateLimit = ActionRateLimit, rate(10, 1_000_001) }), "burst 1000001 is out of range 0-1000000"},
		{"RATE_LIMIT with an ics protocol", actionRule(func(r *Rule) {
			r.Action, r.RateLimit, r.ICS = ActionRateLimit, rate(10, 0), ICSPredicate{Protocol: "dnp3"}
		}), "cannot take an ics protocol"},
		{"RATE_LIMIT with tag", actionRule(func(r *Rule) { r.Action, r.RateLimit, r.Tag = ActionRateLimit, rate(10, 0), "x" }), "tag is only valid with action TAG"},
		{"TAG", actionRule(func(r *Rule) { r.Action, r.Tag = ActionTag, "plc-traffic.v1_a" }), ""},
		{"TAG without a label", actionRule(func(r *Rule) { r.Action = ActionTag }), "tag \"\" is invalid"},
		{"TAG upper case", actionRule(func(r *Rule) { r.Action, r.Tag = ActionTag, "PLC" }), "is invalid"},
		{"TAG leading dot", actionRule(func(r *Rule) { r.Action, r.Tag = ActionTag, ".plc" }), "is invalid"},
		{"TAG 33 characters", actionRule(func(r *Rule) { r.Action, r.Tag = ActionTag, strings.Repeat("a", 33) }), "is invalid"},
		{"TAG 32 characters", actionRule(func(r *Rule) { r.Action, r.Tag = ActionTag, strings.Repeat("a", 32) }), ""},
		{"TAG with a schedule", actionRule(func(r *Rule) { r.Action, r.Tag, r.Schedule = ActionTag, "x", &ScheduleConfig{StartTime: "01:00"} }), "cannot take a schedule"},
		{"TAG with an ics protocol", actionRule(func(r *Rule) { r.Action, r.Tag, r.ICS = ActionTag, "x", ICSPredicate{Protocol: "modbus"} }), "cannot take an ics protocol"},
		{"ALLOW with tag", actionRule(func(r *Rule) { r.Action, r.Tag = ActionAllow, "x" }), "tag is only valid with action TAG"},
		{"DENY with rateLimit", actionRule(func(r *Rule) { r.Action, r.RateLimit = ActionDeny, rate(1, 1) }), "rateLimit is only valid"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := DefaultConfig()
			cfg.Firewall.Rules = []Rule{tc.rule}
			err := cfg.Validate()
			if tc.err == "" {
				if err != nil {
					t.Fatalf("rejected: %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tc.err) {
				t.Fatalf("err = %v, want %q", err, tc.err)
			}
		})
	}
}

func TestValidateResetIsNoDefaultAction(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Firewall.DefaultAction = ActionReset
	if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), "firewall.defaultAction") {
		t.Fatalf("RESET default err = %v", err)
	}
}

func TestValidateTagLabelLimit(t *testing.T) {
	cfg := DefaultConfig()
	for i := 0; i < MaxTagLabels; i++ {
		// Repeating a label does not count it again.
		for _, id := range []string{"a", "b"} {
			cfg.Firewall.Rules = append(cfg.Firewall.Rules, Rule{ID: fmt.Sprintf("t%d%s", i, id), Action: ActionTag, Tag: fmt.Sprintf("label-%d", i)})
		}
	}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("%d labels rejected: %v", MaxTagLabels, err)
	}
	cfg.Firewall.Rules = append(cfg.Firewall.Rules, Rule{ID: "one-more", Action: ActionTag, Tag: "label-x"})
	if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), "limit of 32 distinct tag labels") {
		t.Fatalf("33rd label err = %v", err)
	}
}

func TestRuleActionParametersRoundTrip(t *testing.T) {
	in := []Rule{
		{ID: "police", Action: ActionRateLimit, RateLimit: &RateLimitConfig{PacketsPerSecond: 100, Burst: 20}, ICS: ICSPredicate{}},
		{ID: "label", Action: ActionTag, Tag: "plc", ICS: ICSPredicate{}},
		{ID: "reject", Action: ActionReset, ICS: ICSPredicate{}},
	}
	body, err := json.Marshal(in)
	if err != nil {
		t.Fatal(err)
	}
	var out []Rule
	if err := json.Unmarshal(body, &out); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(out, in) {
		t.Fatalf("round trip:\n%+v\n%+v", in, out)
	}
	if !strings.Contains(string(body), `"rateLimit":{"packetsPerSecond":100,"burst":20}`) || !strings.Contains(string(body), `"tag":"plc"`) {
		t.Fatalf("encoding = %s", body)
	}
}
