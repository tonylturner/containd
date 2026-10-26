// SPDX-License-Identifier: Apache-2.0

package config

import (
	"fmt"
	"strings"
	"testing"
)

func TestValidateIdentityBindings(t *testing.T) {
	many := make([]IdentityBinding, MaxIdentityBindings+1)
	for i := range many {
		many[i] = IdentityBinding{IP: fmt.Sprintf("10.%d.%d.1", i/256, i%256), Identities: []string{"operator"}}
	}
	labels := make([]string, MaxBindingIdentities+1)
	for i := range labels {
		labels[i] = fmt.Sprintf("l%d", i)
	}
	for _, tc := range []struct {
		name     string
		bindings []IdentityBinding
		err      string
	}{
		{"none", nil, ""},
		{"ipv4 and ipv6", []IdentityBinding{{IP: "10.0.0.5", Identities: []string{"operator", "Operator"}}, {IP: "2001:db8::5", Identities: []string{"vendor"}}}, ""},
		{"invalid ip", []IdentityBinding{{IP: "10.0.0", Identities: []string{"operator"}}}, `ip "10.0.0"`},
		{"cidr", []IdentityBinding{{IP: "10.0.0.0/24", Identities: []string{"operator"}}}, "unicast"},
		{"zone", []IdentityBinding{{IP: "fe80::1%eth0", Identities: []string{"operator"}}}, "without a zone"},
		{"unspecified", []IdentityBinding{{IP: "0.0.0.0", Identities: []string{"operator"}}}, "unicast"},
		{"multicast", []IdentityBinding{{IP: "ff02::1", Identities: []string{"operator"}}}, "unicast"},
		{"duplicate ip", []IdentityBinding{{IP: "10.0.0.5", Identities: []string{"a"}}, {IP: "10.0.0.5", Identities: []string{"b"}}}, "already bound"},
		{"duplicate mapped ip", []IdentityBinding{{IP: "10.0.0.5", Identities: []string{"a"}}, {IP: "::ffff:10.0.0.5", Identities: []string{"b"}}}, "10.0.0.5 is already bound"},
		{"no identities", []IdentityBinding{{IP: "10.0.0.5"}}, "needs 1 to"},
		{"too many identities", []IdentityBinding{{IP: "10.0.0.5", Identities: labels}}, "needs 1 to"},
		{"blank identity", []IdentityBinding{{IP: "10.0.0.5", Identities: []string{""}}}, "1 to 64 bytes"},
		{"long identity", []IdentityBinding{{IP: "10.0.0.5", Identities: []string{strings.Repeat("a", MaxIdentityLabelLength+1)}}}, "1 to 64 bytes"},
		{"padded identity", []IdentityBinding{{IP: "10.0.0.5", Identities: []string{" operator"}}}, "surrounding spaces"},
		{"control character", []IdentityBinding{{IP: "10.0.0.5", Identities: []string{"op\nerator"}}}, "non-printable"},
		{"invalid utf-8", []IdentityBinding{{IP: "10.0.0.5", Identities: []string{"op\xffer"}}}, "UTF-8"},
		{"duplicate identity", []IdentityBinding{{IP: "10.0.0.5", Identities: []string{"a", "a"}}}, "listed twice"},
		{"too many bindings", many, "at most 4096"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := DefaultConfig()
			cfg.Firewall.IdentityBindings = tc.bindings
			err := cfg.Validate()
			if (tc.err == "") != (err == nil) || (err != nil && !strings.Contains(err.Error(), tc.err)) {
				t.Fatalf("Validate = %v, want %q", err, tc.err)
			}
		})
	}
}

// TestValidateRuleSchedule checks rule schedules against the enforced
// calendar, including the cutover rule that equal times are invalid.
func TestValidateRuleSchedule(t *testing.T) {
	for _, tc := range []struct {
		sched *ScheduleConfig
		err   string
	}{
		{&ScheduleConfig{DaysOfWeek: []string{"Saturday", "Sunday"}, StartTime: "02:00", EndTime: "06:00", Timezone: "America/New_York"}, ""},
		{&ScheduleConfig{StartTime: "22:00", EndTime: "02:00"}, ""},
		{&ScheduleConfig{Timezone: "Asia/Kolkata"}, ""},
		{&ScheduleConfig{StartTime: "08:00", EndTime: "08:00"}, "rule r1 schedule: endTime 08:00 equals the start time"},
		{&ScheduleConfig{DaysOfWeek: []string{"Funday"}}, `rule r1 schedule: invalid day "Funday"`},
		{&ScheduleConfig{StartTime: "25:00"}, "rule r1 schedule: startTime"},
		{&ScheduleConfig{Timezone: "Nowhere/City"}, `rule r1 schedule: timezone "Nowhere/City"`},
	} {
		cfg := DefaultConfig()
		cfg.Firewall.Rules = append(cfg.Firewall.Rules, Rule{ID: "r1", Action: ActionAllow, Schedule: tc.sched})
		err := cfg.Validate()
		if (tc.err == "") != (err == nil) || (err != nil && !strings.Contains(err.Error(), tc.err)) {
			t.Errorf("schedule %+v: Validate = %v, want %q", *tc.sched, err, tc.err)
		}
	}
}
