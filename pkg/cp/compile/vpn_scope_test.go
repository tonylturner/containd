// SPDX-License-Identifier: Apache-2.0

package compile

import (
	"net"
	"reflect"
	"testing"

	"github.com/tonylturner/containd/pkg/cp/config"
	"github.com/tonylturner/containd/pkg/dp/enforce"
	"github.com/tonylturner/containd/pkg/dp/rules"
)

// A rule side scoped only to a VPN that is not configured must match no
// address on both enforcement paths, never every address.
func TestVPNScopedRuleWithoutVPNMatchesNothing(t *testing.T) {
	sides := map[string]func(*config.Rule, string){
		"source":      func(r *config.Rule, tok string) { r.Sources = []string{tok} },
		"destination": func(r *config.Rule, tok string) { r.Destinations = []string{tok} },
	}
	for side, scope := range sides {
		for _, tok := range []string{"vpn:any", "vpn:all", "vpn:*", "vpn:wireguard", "vpn:wg", "vpn:openvpn", "vpn:ovpn"} {
			for _, action := range []config.Action{config.ActionAllow, config.ActionDeny} {
				t.Run(side+"/"+tok+"/"+string(action), func(t *testing.T) {
					cfg := config.DefaultConfig()
					cfg.Firewall.DefaultAction = config.ActionDeny
					rule := config.Rule{
						ID:        "vpn-scoped",
						Action:    action,
						Protocols: []config.Protocol{{Name: "tcp", Port: "443"}},
					}
					scope(&rule, tok)
					cfg.Firewall.Rules = []config.Rule{rule}

					snap, err := CompileSnapshot(cfg)
					if err != nil {
						t.Fatalf("compile: %v", err)
					}
					if len(snap.Firewall) != 0 {
						t.Fatalf("unmatchable rule compiled to %+v", snap.Firewall)
					}

					// Userspace evaluator: no address reaches the rule.
					ev := rules.NewEvaluator(&snap)
					for _, pair := range [][2]string{{"192.0.2.10", "198.51.100.20"}, {"10.8.0.5", "10.9.0.5"}} {
						got, matched := ev.EvaluateMatch(rules.EvalContext{
							SrcIP: net.ParseIP(pair[0]), DstIP: net.ParseIP(pair[1]),
							Proto: "tcp", Port: "443",
						})
						if matched != nil || got != rules.ActionDeny {
							t.Fatalf("%s -> %s evaluated to %s via %+v", pair[0], pair[1], got, matched)
						}
					}

					// nftables: the ruleset equals one compiled without the rule.
					cfg.Firewall.Rules = nil
					bare, err := CompileSnapshot(cfg)
					if err != nil {
						t.Fatalf("compile bare: %v", err)
					}
					assertSameRuleset(t, &snap, &bare)
				})
			}
		}
	}
}

// Tokens that still expand keep the rule, narrowed to the configured
// addresses.
func TestVPNScopedRulePartialExpansion(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.Services.VPN.WireGuard.Enabled = true
	cfg.Services.VPN.WireGuard.AddressCIDR = "10.8.0.1/24"
	cfg.Firewall.Rules = []config.Rule{
		{ID: "ovpn-or-lan", Action: config.ActionAllow, Sources: []string{"vpn:openvpn", "192.0.2.0/24"}},
		{ID: "ovpn-only", Action: config.ActionAllow, Destinations: []string{"vpn:openvpn"}},
		{ID: "any-vpn", Action: config.ActionAllow, Destinations: []string{"vpn:any"}},
	}
	snap, err := CompileSnapshot(cfg)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	got := map[string]rules.Entry{}
	for _, e := range snap.Firewall {
		got[e.ID] = e
	}
	if len(got) != 2 {
		t.Fatalf("expected ovpn-or-lan and any-vpn only, got %+v", snap.Firewall)
	}
	if s := got["ovpn-or-lan"].Sources; !reflect.DeepEqual(s, []string{"192.0.2.0/24"}) {
		t.Fatalf("ovpn-or-lan sources = %v", s)
	}
	if d := got["any-vpn"].Destinations; !reflect.DeepEqual(d, []string{"10.8.0.1/24"}) {
		t.Fatalf("any-vpn destinations = %v", d)
	}
}

func assertSameRuleset(t *testing.T, got, want *rules.Snapshot) {
	t.Helper()
	c := enforce.NewCompiler()
	gotNft, err := c.CompileFirewall(got)
	if err != nil {
		t.Fatalf("compile nft: %v", err)
	}
	wantNft, err := c.CompileFirewall(want)
	if err != nil {
		t.Fatalf("compile bare nft: %v", err)
	}
	if gotNft != wantNft {
		t.Fatalf("ruleset differs from one without the rule:\n%s\n--- want ---\n%s", gotNft, wantNft)
	}
}
