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
	for _, chain := range []string{"input", "forward", "revocation_output"} {
		start := strings.Index(text, "chain "+chain+" {")
		end := strings.Index(text[start:], "  }") + start
		s := text[start:end]
		jump := strings.Index(s, "jump revocations;")
		accept := strings.Index(s, "accept;")
		if jump < 0 || (accept >= 0 && jump > accept && chain != "revocation_output") {
			t.Fatalf("revocation ordering:\n%s", s)
		}
	}
	for _, key := range []string{"ct state { invalid, untracked } ip saddr", "tcp flags & rst == rst return;", "ct original ip saddr", "ct original ip6 saddr", "@revoke_service4", "@revoke_service6", "@revoke4 reject with tcp reset", "@revoke6 drop"} {
		if !strings.Contains(text, key) {
			t.Fatalf("missing %s", key)
		}
	}
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

func TestRevocationInvalidKeys(t *testing.T) {
	e := conntrack.Entry{Proto: "tcp", Src: "192.0.2.1", Dst: "192.0.2.2", Sport: "1234", Dport: "443", ReplySrc: "192.0.2.2", ReplyDst: "192.0.2.1", ReplySport: "443", ReplyDport: "1234"}
	for _, change := range []func(*conntrack.Entry){func(e *conntrack.Entry) { e.Proto = "icmp" }, func(e *conntrack.Entry) { e.ReplyDport = "65536" }, func(e *conntrack.Entry) { e.ReplySrc = "2001:db8::1" }, func(e *conntrack.Entry) { e.ReplyDst = "192.0.2.1; flush ruleset" }} {
		bad := e
		change(&bad)
		if _, err := NewNftUpdater("containd").revocationBatch([]conntrack.Entry{bad}, "connection", time.Minute); err == nil {
			t.Fatalf("accepted %+v", bad)
		}
	}
	for _, ttl := range []time.Duration{0, time.Millisecond, 2 * time.Hour} {
		if _, err := NewNftUpdater("containd").revocationBatch([]conntrack.Entry{e}, "connection", ttl); err == nil {
			t.Fatalf("accepted ttl %s", ttl)
		}
	}
}
