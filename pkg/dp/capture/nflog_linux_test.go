// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

//go:build linux

package capture

import (
	"strings"
	"testing"

	nflog "github.com/florianl/go-nflog/v2"
)

// strPtr is a small helper to build nflog.Attribute.Prefix (which is a
// *string in the upstream API).
func strPtr(s string) *string { return &s }

// bytesPtr is a small helper to build nflog.Attribute.Payload (which is
// a *[]byte in the upstream API).
func bytesPtr(b []byte) *[]byte { return &b }

func TestBuildRuleHitEventParsesPrefix(t *testing.T) {
	a := nflog.Attribute{
		Prefix: strPtr("containd:deny-ent-to-field:DENY "),
	}
	ev, ok := buildRuleHitEvent(a)
	if !ok {
		t.Fatal("expected event, got !ok")
	}
	if ev.Kind != "firewall.rule.hit" {
		t.Errorf("Kind = %q, want firewall.rule.hit", ev.Kind)
	}
	if got, want := ev.Attributes["ruleId"], "deny-ent-to-field"; got != want {
		t.Errorf("ruleId = %v, want %q", got, want)
	}
	if got, want := ev.Attributes["action"], "DENY"; got != want {
		t.Errorf("action = %v, want %q", got, want)
	}
	if got, want := ev.Attributes["via"], "nflog"; got != want {
		t.Errorf("via = %v, want %q", got, want)
	}
}

func TestBuildRuleHitEventRejectsForeignPrefix(t *testing.T) {
	cases := []string{
		"some other kernel log message",
		"containd:",
		"containd:rule:lowercase",
		"",
	}
	for _, c := range cases {
		c := c
		t.Run(c, func(t *testing.T) {
			a := nflog.Attribute{Prefix: strPtr(c)}
			if _, ok := buildRuleHitEvent(a); ok {
				t.Errorf("expected !ok for prefix %q", c)
			}
		})
	}
}

func TestBuildRuleHitEventNoPrefixIsNoop(t *testing.T) {
	a := nflog.Attribute{} // Prefix nil
	if _, ok := buildRuleHitEvent(a); ok {
		t.Error("expected !ok when no prefix is set")
	}
}

func TestBuildRuleHitEventExtractsPacketFields(t *testing.T) {
	// Minimal IPv4+TCP packet: src 10.10.10.50 -> dst 10.40.40.20:502.
	// 20-byte IPv4 header (no options) + 20-byte TCP header, no payload.
	pkt := []byte{
		// IPv4 header
		0x45,             // version=4, ihl=5
		0x00,             // dscp+ecn
		0x00, 0x28,       // total length = 40
		0x00, 0x00,       // identification
		0x40, 0x00,       // flags + fragment offset
		0x40,             // ttl
		0x06,             // protocol = TCP
		0x00, 0x00,       // header checksum (zero, not validated)
		10, 10, 10, 50,   // src 10.10.10.50
		10, 40, 40, 20,   // dst 10.40.40.20
		// TCP header (20 bytes)
		0xc0, 0x00,       // src port 49152
		0x01, 0xf6,       // dst port 502 (Modbus)
		0x00, 0x00, 0x00, 0x00, // seq
		0x00, 0x00, 0x00, 0x00, // ack
		0x50, 0x02,       // data offset 5, SYN flag
		0x20, 0x00,       // window
		0x00, 0x00,       // checksum
		0x00, 0x00,       // urgent
	}
	a := nflog.Attribute{
		Prefix:  strPtr("containd:fw-test:DENY "),
		Payload: bytesPtr(pkt),
	}
	ev, ok := buildRuleHitEvent(a)
	if !ok {
		t.Fatal("expected event, got !ok")
	}
	if ev.SrcIP != "10.10.10.50" {
		t.Errorf("SrcIP = %q, want 10.10.10.50", ev.SrcIP)
	}
	if ev.DstIP != "10.40.40.20" {
		t.Errorf("DstIP = %q, want 10.40.40.20", ev.DstIP)
	}
	if ev.SrcPort != 49152 {
		t.Errorf("SrcPort = %d, want 49152", ev.SrcPort)
	}
	if ev.DstPort != 502 {
		t.Errorf("DstPort = %d, want 502", ev.DstPort)
	}
	if ev.Transport != "tcp" {
		t.Errorf("Transport = %q, want tcp", ev.Transport)
	}
	if ev.Attributes["proto"] != "tcp" {
		t.Errorf("proto attribute = %v, want tcp", ev.Attributes["proto"])
	}
	if ev.Attributes["port"] != "502" {
		t.Errorf("port attribute = %v, want \"502\"", ev.Attributes["port"])
	}
}

func TestRulePrefixREAcceptsTypicalForms(t *testing.T) {
	cases := []struct {
		prefix string
		id     string
		action string
	}{
		{"containd:foo:ALLOW ", "foo", "ALLOW"},
		{"containd:deny-enterprise-to-field:DENY ", "deny-enterprise-to-field", "DENY"},
		{"containd:rtac-to-field-modbus:ALLOW", "rtac-to-field-modbus", "ALLOW"},
		{"containd:underscores_ok_too:ALLOW ", "underscores_ok_too", "ALLOW"},
	}
	for _, c := range cases {
		c := c
		t.Run(c.prefix, func(t *testing.T) {
			m := rulePrefixRE.FindStringSubmatch(strings.TrimSpace(c.prefix))
			if m == nil {
				t.Fatalf("expected match for %q", c.prefix)
			}
			if m[1] != c.id || m[2] != c.action {
				t.Errorf("got (%q, %q), want (%q, %q)", m[1], m[2], c.id, c.action)
			}
		})
	}
}
