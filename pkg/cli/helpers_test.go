// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

package cli

import (
	"bytes"
	"context"
	"net/http"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/tonylturner/containd/pkg/cp/config"
)

func TestCLIFormatHelpers(t *testing.T) {
	t.Parallel()

	if got := joinCSV(nil); got != "—" {
		t.Fatalf("joinCSV(nil) = %q", got)
	}
	if got := joinCSV([]string{"a", "b"}); got != "a,b" {
		t.Fatalf("joinCSV(non-empty) = %q", got)
	}
	if got := splitCSV(" a, ,b "); len(got) != 2 || got[0] != "a" || got[1] != "b" {
		t.Fatalf("splitCSV = %#v", got)
	}
	if got := yesNoStr(true); got != "yes" {
		t.Fatalf("yesNoStr(true) = %q", got)
	}
	if got := firstNonEmpty("", "fallback", "later"); got != "fallback" {
		t.Fatalf("firstNonEmpty = %q", got)
	}
	if got := fmtTime(time.Time{}); got != "—" {
		t.Fatalf("fmtTime(zero) = %q", got)
	}
	if got := fmtTime(time.Date(2026, 3, 13, 17, 0, 0, 0, time.UTC)); got != "2026-03-13T17:00:00Z" {
		t.Fatalf("fmtTime(non-zero) = %q", got)
	}
	if got := truncate("abcdef", 4); got != "abc…" {
		t.Fatalf("truncate = %q", got)
	}
	if got := attrsSummary(map[string]any{"b": 2, "a": "x"}, 64); got != "a=x b=2" {
		t.Fatalf("attrsSummary = %q", got)
	}

	var buf bytes.Buffer
	tbl := newTable("COL1", "COL2")
	tbl.addRow("a", "bbb")
	tbl.render(&buf)
	if !strings.Contains(buf.String(), "COL1") || !strings.Contains(buf.String(), "bbb") {
		t.Fatalf("unexpected table output: %q", buf.String())
	}
}

func TestOutboundQuickstartHelpers(t *testing.T) {
	t.Parallel()

	wan := pickWAN([]outboundIface{
		{Name: "lan1", Zone: "lan"},
		{Name: "uplink0", Zone: "wan"},
	})
	if wan == nil || wan.Name != "uplink0" {
		t.Fatalf("pickWAN(zone) = %#v", wan)
	}
	wan = pickWAN([]outboundIface{{Name: "wan", Zone: "dmz"}})
	if wan == nil || wan.Name != "wan" {
		t.Fatalf("pickWAN(name) = %#v", wan)
	}

	if got := pickWANIPv4CIDR([]outboundIfaceState{
		{Name: "eth0", Addrs: []string{"169.254.1.1/16", "10.0.0.5/24", "fe80::1/64"}},
	}, "eth0"); got != "10.0.0.5/24" {
		t.Fatalf("pickWANIPv4CIDR = %q", got)
	}

	if !isDefaultQuickstartRoute("default") || !isDefaultQuickstartRoute("0.0.0.0/0") || isDefaultQuickstartRoute("10.0.0.0/24") {
		t.Fatal("isDefaultQuickstartRoute returned unexpected result")
	}
	if got := urlEscape("rule 1/a?b#c"); got != "rule%201%2Fa%3Fb%23c" {
		t.Fatalf("urlEscape = %q", got)
	}
}

func TestFirewallICSParsingHelpers(t *testing.T) {
	t.Parallel()

	rule, err := parseFirewallICSRuleArgs([]string{
		"allow-modbus",
		"ALLOW",
		"modbus",
		"--src-zone", "lan",
		"--dst-zone", "wan",
		"--function-code", "3,16",
		"--unit-id", "7",
		"--addresses", "0x0100-0x01FF,0x0200",
		"--read-only",
		"--mode", "enforce",
	})
	if err != nil {
		t.Fatalf("parseFirewallICSRuleArgs(valid): %v", err)
	}
	if rule.ID != "allow-modbus" || rule.ICS.Protocol != "modbus" || len(rule.ICS.FunctionCode) != 2 || rule.ICS.UnitID == nil || *rule.ICS.UnitID != 7 || !rule.ICS.ReadOnly || rule.ICS.Mode != "enforce" {
		t.Fatalf("unexpected parsed rule: %#v", rule)
	}

	if _, err := parseFirewallICSRuleArgs([]string{"id", "ALLOW"}); err == nil {
		t.Fatal("expected usage error")
	}
	if _, err := parseFirewallICSRuleArgs([]string{"id", "ALLOW", "modbus", "--mode", "bad"}); err == nil {
		t.Fatal("expected invalid mode error")
	}
	if _, err := parseFirewallICSRuleArgs([]string{"id", "ALLOW", "modbus", "--function-code", "abc"}); err == nil {
		t.Fatal("expected invalid function-code error")
	}
	if _, err := parseFirewallICSRuleArgs([]string{"id", "ALLOW", "modbus", "--unknown"}); err == nil {
		t.Fatal("expected unknown option error")
	}
}

func TestFirewallIEC104RuleFlags(t *testing.T) {
	t.Parallel()

	rule, err := parseFirewallICSRuleArgs([]string{
		"allow-commands",
		"ALLOW",
		"iec104",
		"--type-ids", "45,46",
		"--classes", "monitor,control",
		"--ca", "1,65534",
		"--ioa", "0,65536-65567,16777215",
		"--read-only",
		"--direction", "request",
		"--mode", "enforce",
	})
	if err != nil {
		t.Fatalf("parse IEC104 flags: %v", err)
	}
	if got := rule.ICS.TypeIDs; len(got) != 2 || got[0] != 45 || got[1] != 46 {
		t.Fatalf("type IDs = %v, want [45 46]", got)
	}
	if got := rule.ICS.Classes; len(got) != 2 || got[0] != "monitor" || got[1] != "control" {
		t.Fatalf("classes = %v, want [monitor control]", got)
	}
	if got := rule.ICS.CA; len(got) != 2 || got[0] != 1 || got[1] != 65534 {
		t.Fatalf("CA = %v, want [1 65534]", got)
	}
	wantIOA := []config.IOARange{{Start: 0, End: 0}, {Start: 65536, End: 65567}, {Start: 16777215, End: 16777215}}
	if !reflect.DeepEqual(rule.ICS.IOA, wantIOA) {
		t.Fatalf("IOA ranges = %v, want %v", rule.ICS.IOA, wantIOA)
	}
	if !rule.ICS.ReadOnly || rule.ICS.Direction != "request" || rule.ICS.Mode != "enforce" {
		t.Fatalf("readOnly/direction/mode = %t/%q/%q", rule.ICS.ReadOnly, rule.ICS.Direction, rule.ICS.Mode)
	}

	tests := []struct {
		name  string
		flags []string
	}{
		{"type ID zero", []string{"--type-ids", "0"}},
		{"type ID too large", []string{"--type-ids", "256"}},
		{"invalid class", []string{"--classes", "commands"}},
		{"broadcast CA", []string{"--ca", "65535"}},
		{"IOA above 24 bits", []string{"--ioa", "16777216"}},
		{"reversed IOA", []string{"--ioa", "10-1"}},
		{"invalid direction", []string{"--direction", "both"}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			args := append([]string{"id", "ALLOW", "iec104"}, tc.flags...)
			if _, err := parseFirewallICSRuleArgs(args); err == nil {
				t.Fatalf("parse flags %v succeeded, want error", tc.flags)
			}
		})
	}
}

func TestShowFirewallICSRulesIncludesIEC104Fields(t *testing.T) {
	t.Parallel()

	rule := config.Rule{
		ID:     "iec-read",
		Action: config.ActionAllow,
		ICS: config.ICSPredicate{
			Protocol:  "iec104",
			TypeIDs:   []int{45, 46},
			Classes:   []string{"monitor"},
			CA:        []uint16{1},
			IOA:       []config.IOARange{{Start: 65536, End: 65567}},
			ReadOnly:  true,
			Direction: "response",
			Mode:      "enforce",
		},
	}
	inherited := config.Rule{
		ID:     "iec-inherited",
		Action: config.ActionAllow,
		ICS:    config.ICSPredicate{Protocol: "iec104", ReadOnly: true},
	}
	client := &dispatchHTTPClient{
		t: t,
		handlers: map[string]func(*http.Request) (*http.Response, error){
			"GET /api/v1/firewall/ics-rules": func(*http.Request) (*http.Response, error) {
				return jsonHTTPResponse(http.StatusOK, []config.Rule{rule, inherited}, nil), nil
			},
			"GET /api/v1/dataplane": func(*http.Request) (*http.Response, error) {
				return jsonHTTPResponse(http.StatusOK, config.DataPlaneConfig{DPIMode: "enforce"}, nil), nil
			},
		},
	}
	api := &API{BaseURL: "http://localhost", Client: client}
	var out bytes.Buffer
	if err := showFirewallICSRulesAPI(api)(context.Background(), &out, nil); err != nil {
		t.Fatalf("show IEC104 rules: %v", err)
	}
	for _, want := range []string{"TYPE_IDS", "CLASSES", "CA", "IOA", "DIRECTION", "45,46", "monitor", "65536-65567", "response", "enforce (effective: enforce)", "inherit (enforce)"} {
		if !strings.Contains(out.String(), want) {
			t.Fatalf("output = %q, want %q", out.String(), want)
		}
	}
}
