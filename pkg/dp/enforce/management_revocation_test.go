// SPDX-License-Identifier: Apache-2.0

package enforce

import (
	"net/netip"
	"strings"
	"testing"

	"github.com/tonylturner/containd/pkg/common/mgmtpath"
	"github.com/tonylturner/containd/pkg/dp/rules"
)

// chainRules lists the rules a blocks-table script adds to chain, in order.
func chainRules(text, chain string) []string {
	var out []string
	prefix := "add rule inet containd " + chain + " "
	for _, line := range strings.Split(text, "\n") {
		if strings.HasPrefix(line, prefix) {
			out = append(out, strings.TrimPrefix(line, prefix))
		}
	}
	return out
}

func TestManagementTrafficPassesRevocations(t *testing.T) {
	live, err := mgmtpath.Devices()
	if err != nil || len(live) == 0 {
		t.Skipf("no live non-loopback device: %v", err)
	}
	dev := live[0]
	c := NewCompiler()
	c.ManagementReservation = &mgmtpath.Reservation{Device: "mgmt0", Local: netip.MustParsePrefix("10.99.0.1/24"),
		Sources: []netip.Addr{netip.MustParseAddr("10.99.0.10")}, Port: 9000}
	text, err := c.CompileFirewall(&rules.Snapshot{LocalInput: []rules.LocalServiceRule{
		{ID: "auto-allow-mgmt-https", Proto: "tcp", Port: 8443, Ifaces: []string{dev}, RecoverUnbound: true},
		{ID: "vpn", Proto: "udp", Port: 51820, Ifaces: []string{dev}},
	}})
	if err != nil {
		t.Fatal(err)
	}
	want := map[string][]string{
		"input": {
			`iifname "mgmt0" ip saddr { 10.99.0.10 } ip daddr 10.99.0.1 tcp dport 9000 accept`,
			`iifname { "` + dev + `" } tcp dport 8443 accept`,
			"jump revocations",
		},
		"output": {
			`oifname "mgmt0" ip saddr 10.99.0.1 ip daddr { 10.99.0.10 } tcp sport 9000 accept`,
			`oifname { "` + dev + `" } tcp sport 8443 accept`,
			"jump revocations",
		},
	}
	// Other local services (the VPN listener) get no exemption.
	for chain, lines := range want {
		if got := chainRules(text, chain); strings.Join(got, "\n") != strings.Join(lines, "\n") {
			t.Fatalf("%s chain:\n%s\nwant:\n%s", chain, strings.Join(got, "\n"), strings.Join(lines, "\n"))
		}
	}
	// Forwarded traffic is not management traffic.
	if fwd := chainRules(text, "forward"); len(fwd) == 0 || fwd[0] != "jump revocations" {
		t.Fatalf("forward chain:\n%s", strings.Join(fwd, "\n"))
	}
}

func TestManagementExemptionsFollowResolvedListeners(t *testing.T) {
	// A listener that resolves to no interface is omitted from the policy
	// and from the exemptions alike.
	in, out, err := NewCompiler().managementExemptions(nil)
	if err != nil || in != nil || out != nil {
		t.Fatalf("in=%v out=%v err=%v", in, out, err)
	}
	if _, _, err := NewCompiler().managementExemptions([]rules.LocalServiceRule{{ID: "bad", Proto: "icmp", Port: 1, Ifaces: []string{"eth0"}, RecoverUnbound: true}}); err == nil {
		t.Fatal("invalid management listener accepted")
	}
}
