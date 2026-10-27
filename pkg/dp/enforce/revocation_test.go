// SPDX-License-Identifier: Apache-2.0
package enforce

import (
	"strings"
	"testing"
	"time"

	"github.com/tonylturner/containd/pkg/dp/conntrack"
	"github.com/tonylturner/containd/pkg/dp/rules"
)

func TestRevocationRules(t *testing.T) {
	text, err := NewCompiler().CompileFirewall(&rules.Snapshot{})
	if err != nil {
		t.Fatal(err)
	}
	// Revocations live in the dynamic table, whose input, forward and output
	// chains run before the policy table's and jump to them before any
	// other rule. The policy table neither declares nor references them.
	policy := text[:strings.Index(text, "add table inet containd\n")]
	if strings.Contains(policy, "revoke") || strings.Contains(policy, "revocations") {
		t.Fatalf("policy table holds revocation state:\n%s", policy)
	}
	for _, chain := range []string{"input", "forward", "output"} {
		hook := "add chain inet containd " + chain + " { type filter hook " + chain + " priority -10; policy accept; }\n"
		first := "add rule inet containd " + chain + " "
		if !strings.Contains(text, hook) || !strings.HasPrefix(text[strings.Index(text, first):], first+"jump revocations\n") {
			t.Fatalf("revocation ordering in %s:\n%s", chain, text)
		}
	}
	if strings.Index(text, "add rule inet containd forward jump revocations") > strings.Index(text, "@block_hosts drop") {
		t.Fatalf("revocations must precede blocks:\n%s", text)
	}
	for _, key := range []string{"ct state { invalid, untracked } ip saddr", "revocations tcp flags & rst == rst return\n", "ct original ip saddr", "ct original ip6 saddr", "@revoke_service4", "@revoke_service6", "@revoke4 reject with tcp reset", "@revoke6 drop",
		"meta l4proto icmp ct protocol icmp ct original ip saddr . ct original ip daddr . meta l4proto . ct original proto-src . ct original proto-dst @revoke4 drop\n",
		"meta l4proto icmp ct state { invalid, untracked } ip saddr . ip daddr . meta l4proto . th sport @revoke_service4 drop\n",
		"meta l4proto icmp ct protocol icmp ct original ip saddr . ct original ip daddr . meta l4proto . ct original proto-dst @revoke_service4 drop\n",
		"meta l4proto icmpv6 ct protocol icmpv6 ct original ip6 saddr . ct original ip6 daddr . meta l4proto . ct original proto-src . ct original proto-dst @revoke6 drop\n",
		"meta l4proto icmpv6 ct state { invalid, untracked } ip6 saddr . ip6 daddr . meta l4proto . th sport @revoke_service6 drop\n",
		"meta l4proto icmpv6 ct protocol icmpv6 ct original ip6 saddr . ct original ip6 daddr . meta l4proto . ct original proto-dst @revoke_service6 drop\n",
		"meta l4proto icmp ct state { invalid, untracked } ip saddr . ip daddr . icmp id @revoke_icmp4 drop\n",
		"meta l4proto icmpv6 ct state { invalid, untracked } ip6 saddr . ip6 daddr . icmpv6 id @revoke_icmp6 drop\n",
		"add set inet containd revoke_icmp4 { typeof ip saddr . ip daddr . icmp id; flags timeout; }\n",
		"add set inet containd revoke_icmp6 { typeof ip6 saddr . ip6 daddr . icmpv6 id; flags timeout; }\n"} {
		if !strings.Contains(text, key) {
			t.Fatalf("missing %s", key)
		}
	}
	assertDeclaredSets(t, text)
}

func TestRevocationNATKeys(t *testing.T) {
	for _, e := range []conntrack.Entry{{Proto: "tcp", Src: "192.0.2.1", Dst: "198.51.100.1", Sport: "1234", Dport: "443", ReplySrc: "10.0.0.1", ReplyDst: "203.0.113.1", ReplySport: "8443", ReplyDport: "5678"}, {Proto: "udp", Src: "2001:db8::1", Dst: "2001:db8::2", Sport: "1234", Dport: "443", ReplySrc: "2001:db8:1::1", ReplyDst: "2001:db8:1::2", ReplySport: "8443", ReplyDport: "5678"}} {
		for _, scope := range []string{"connection", "client-service"} {
			s, err := NewNftUpdater("containd").revocationBatch([]conntrack.Entry{e}, scope, 30*time.Second)
			if err != nil {
				t.Fatal(err)
			}
			if !strings.Contains(s, e.Src+" . "+e.Dst+" . "+e.Proto+" . 1234 . 443 timeout 30s") || !strings.Contains(s, e.ReplySrc+" . "+e.ReplyDst+" . "+e.Proto+" . 8443 . 5678 timeout 30s") {
				t.Fatalf("missing tuple: %s", s)
			}
			for _, line := range strings.Split(strings.TrimSpace(s), "\n") {
				if !strings.HasPrefix(line, "add element inet containd revoke") {
					t.Fatalf("revocation outside the dynamic table: %s", line)
				}
			}
			if (scope == "client-service") != strings.Contains(s, "revoke_service") {
				t.Fatal(s)
			}
			for _, line := range strings.Split(s, "\n") {
				if strings.Contains(line, "revoke_service") && strings.Contains(line, e.ReplyDst) {
					t.Fatalf("broad SNAT reply key: %s", line)
				}
			}
		}
	}
}

// The tracked ICMP key is the original tuple, with the identifier in the
// source port field and type * 256 + code in the destination port field; the
// service key is the query type and code. Untracked packets are keyed by the
// addresses and identifier of each direction, the reply's as NAT rewrote it.
func TestRevocationICMPKeys(t *testing.T) {
	for _, tc := range []struct {
		e                 conntrack.Entry
		connection, broad string
	}{
		{conntrack.Entry{Proto: "icmp", Src: "192.0.2.1", Dst: "198.51.100.1", ICMPID: "4660", ICMPType: "8", ICMPCode: "0", ReplySrc: "10.0.0.1", ReplyDst: "203.0.113.1", ReplyICMPID: "7", ReplyICMPType: "0", ReplyICMPCode: "0"},
			"add element inet containd revoke4 { 192.0.2.1 . 198.51.100.1 . icmp . 4660 . 2048 timeout 30s }\n" +
				"add element inet containd revoke_icmp4 { 10.0.0.1 . 203.0.113.1 . 7 timeout 30s }\n" +
				"add element inet containd revoke_icmp4 { 192.0.2.1 . 198.51.100.1 . 4660 timeout 30s }\n",
			"add element inet containd revoke_service4 { 192.0.2.1 . 198.51.100.1 . icmp . 2048 timeout 30s }\n"},
		{conntrack.Entry{Proto: "icmpv6", Src: "2001:db8::1", Dst: "2001:db8::2", ICMPID: "0", ICMPType: "128", ICMPCode: "0", ReplySrc: "2001:db8::2", ReplyDst: "2001:db8::1", ReplyICMPID: "0", ReplyICMPType: "129", ReplyICMPCode: "0"},
			"add element inet containd revoke6 { 2001:db8::1 . 2001:db8::2 . icmpv6 . 0 . 32768 timeout 30s }\n" +
				"add element inet containd revoke_icmp6 { 2001:db8::1 . 2001:db8::2 . 0 timeout 30s }\n" +
				"add element inet containd revoke_icmp6 { 2001:db8::2 . 2001:db8::1 . 0 timeout 30s }\n",
			"add element inet containd revoke_service6 { 2001:db8::1 . 2001:db8::2 . icmpv6 . 32768 timeout 30s }\n"},
	} {
		for scope, want := range map[string]string{"connection": tc.connection, "client-service": tc.connection + tc.broad} {
			got, err := NewNftUpdater("containd").revocationBatch([]conntrack.Entry{tc.e}, scope, 30*time.Second)
			if err != nil || got != want {
				t.Fatalf("%s %s:\n%s\nwant:\n%s (%v)", tc.e.Proto, scope, got, want, err)
			}
		}
	}
}

func TestRevocationInvalidKeys(t *testing.T) {
	e := conntrack.Entry{Proto: "tcp", Src: "192.0.2.1", Dst: "192.0.2.2", Sport: "1234", Dport: "443", ReplySrc: "192.0.2.2", ReplyDst: "192.0.2.1", ReplySport: "443", ReplyDport: "1234"}
	for _, change := range []func(*conntrack.Entry){func(e *conntrack.Entry) { e.Proto = "icmp" }, func(e *conntrack.Entry) { e.ReplyDport = "65536" }, func(e *conntrack.Entry) { e.ReplySrc = "2001:db8::1" }, func(e *conntrack.Entry) { e.ReplyDst = "192.0.2.1; flush ruleset" }} {
		bad := e
		change(&bad)
		if _, err := NewNftUpdater("containd").revocationBatch([]conntrack.Entry{bad}, "connection", time.Minute); err == nil {
			t.Fatalf("accepted %+v", bad)
		}
	}
	ping := conntrack.Entry{Proto: "icmp", Src: "192.0.2.1", Dst: "192.0.2.2", ICMPID: "1", ICMPType: "8", ICMPCode: "0", ReplySrc: "192.0.2.2", ReplyDst: "192.0.2.1", ReplyICMPID: "1", ReplyICMPType: "0", ReplyICMPCode: "0"}
	if _, err := NewNftUpdater("containd").revocationBatch([]conntrack.Entry{ping}, "client-service", time.Minute); err != nil {
		t.Fatal(err)
	}
	for _, change := range []func(*conntrack.Entry){func(e *conntrack.Entry) { e.ICMPType = "3" }, func(e *conntrack.Entry) { e.ICMPID = "65536" }, func(e *conntrack.Entry) { e.ICMPID = "" }, func(e *conntrack.Entry) { e.Proto = "icmpv6" }, func(e *conntrack.Entry) { e.Dst = "2001:db8::1" },
		func(e *conntrack.Entry) { e.ReplyICMPID = "" }, func(e *conntrack.Entry) { e.ReplyICMPID = "65536" }, func(e *conntrack.Entry) { e.ReplySrc = "2001:db8::2" }, func(e *conntrack.Entry) { e.ReplyDst = "192.0.2.1; flush ruleset" }} {
		bad := ping
		change(&bad)
		if _, err := NewNftUpdater("containd").revocationBatch([]conntrack.Entry{bad}, "client-service", time.Minute); err == nil {
			t.Fatalf("accepted %+v", bad)
		}
	}
	for _, ttl := range []time.Duration{0, time.Millisecond, 2 * time.Hour} {
		if _, err := NewNftUpdater("containd").revocationBatch([]conntrack.Entry{e}, "connection", ttl); err == nil {
			t.Fatalf("accepted ttl %s", ttl)
		}
	}
}
