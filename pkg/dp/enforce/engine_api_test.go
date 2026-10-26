// SPDX-License-Identifier: Apache-2.0

package enforce

import (
	"fmt"
	"net/netip"
	"strings"
	"testing"

	"github.com/tonylturner/containd/pkg/dp/rules"
)

// The input chain admits the engine API from loopback, and from elsewhere
// only on the path the listener is bound to; revocations never cut it.
func TestEngineAPIAdmittedOnlyOnItsPath(t *testing.T) {
	snap := &rules.Snapshot{Default: rules.ActionDeny}
	c := NewCompiler()
	text, err := c.CompileFirewall(snap)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(text, "dport 8081") {
		t.Fatalf("engine API admitted without a path:\n%s", text)
	}
	for _, tc := range []struct {
		path       EngineAPIPath
		input, out string
	}{
		{EngineAPIPath{Device: "eth1", Addr: netip.MustParseAddr("198.51.100.2"), Port: 9091},
			`iifname "eth1" ip daddr 198.51.100.2 tcp dport 9091 accept`,
			`oifname "eth1" ip saddr 198.51.100.2 tcp sport 9091 accept`},
		{EngineAPIPath{Device: "eth2", Addr: netip.MustParseAddr("2001:db8::2"), Port: 8081},
			`iifname "eth2" ip6 daddr 2001:db8::2 tcp dport 8081 accept`,
			`oifname "eth2" ip6 saddr 2001:db8::2 tcp sport 8081 accept`},
	} {
		c.EngineAPI = &tc.path
		text, err := c.CompileFirewall(snap)
		if err != nil {
			t.Fatal(err)
		}
		policy := text[:strings.Index(text, "add table inet containd\n")]
		if !strings.Contains(policy, "  chain input {") || strings.Count(policy, tc.input+";") != 1 {
			t.Fatalf("policy input lacks %q:\n%s", tc.input, policy)
		}
		for chain, rule := range map[string]string{"input": tc.input, "output": tc.out} {
			if !strings.Contains(text, "add rule inet containd "+chain+" "+rule+"\n") {
				t.Fatalf("dynamic %s lacks exemption %q:\n%s", chain, rule, text)
			}
		}
		// The policy rule and the revocation exemption, nothing else.
		if strings.Count(text, fmt.Sprintf("tcp dport %d ", tc.path.Port)) != 2 {
			t.Fatalf("engine API admitted beyond its path:\n%s", text)
		}
	}
}
