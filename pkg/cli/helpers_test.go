// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

package cli

import (
	"bytes"
	"strings"
	"testing"
	"time"
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

	if got, err := firstHostInCIDR("10.0.0.5/24"); err != nil || got != "10.0.0.1" {
		t.Fatalf("firstHostInCIDR(valid) = %q, %v", got, err)
	}
	if _, err := firstHostInCIDR("10.0.0.0/31"); err == nil {
		t.Fatal("expected too-small CIDR error")
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
