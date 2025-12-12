package enforce

import (
	"net"
	"strings"
	"testing"
	"time"

	"github.com/containd/containd/pkg/dp/rules"
)

func TestCompileFirewallBasic(t *testing.T) {
	compiler := NewCompiler()
	snap := &rules.Snapshot{
		Default: rules.ActionDeny,
		Firewall: []rules.Entry{
			{ID: "10", Action: rules.ActionAllow, Protocols: []rules.Protocol{{Name: "tcp", Port: "80"}}},
			{ID: "20", Action: rules.ActionDeny, Sources: []string{"10.0.0.0/8"}},
		},
	}
	ruleset, err := compiler.CompileFirewall(snap)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	if !strings.Contains(ruleset, "table inet containd") {
		t.Fatalf("missing table: %s", ruleset)
	}
	if !strings.Contains(ruleset, "set block_hosts") || !strings.Contains(ruleset, "set block_flows") {
		t.Fatalf("missing dynamic sets")
	}
	if !strings.Contains(ruleset, "policy drop") {
		t.Fatalf("missing default drop policy")
	}
	if !strings.Contains(ruleset, "comment \"10\" tcp dport 80 accept") {
		t.Fatalf("missing allow rule")
	}
	if !strings.Contains(ruleset, "comment \"20\" ip saddr { 10.0.0.0/8 } drop") {
		t.Fatalf("missing deny rule")
	}
}

func TestCompileFirewallZoneBindings(t *testing.T) {
	compiler := NewCompiler()
	snap := &rules.Snapshot{
		Default: rules.ActionDeny,
		ZoneIfaces: map[string][]string{
			"wan": {"wan"},
			"lan": {"lan2", "lan3"},
		},
		Firewall: []rules.Entry{
			{
				ID:          "z1",
				SourceZones: []string{"lan"},
				DestZones:   []string{"wan"},
				Protocols:   []rules.Protocol{{Name: "tcp", Port: "80"}},
				Action:      rules.ActionAllow,
			},
		},
	}
	ruleset, err := compiler.CompileFirewall(snap)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	if !strings.Contains(ruleset, "set zone_lan_ifaces") || !strings.Contains(ruleset, "type ifname") {
		t.Fatalf("missing zone iface sets: %s", ruleset)
	}
	if !strings.Contains(ruleset, "iifname { \"lan2\", \"lan3\" }") || !strings.Contains(ruleset, "oifname { \"wan\" }") {
		t.Fatalf("missing iif/oif bindings: %s", ruleset)
	}
}

func TestNftUpdaterArgsFormatting(t *testing.T) {
	u := NewNftUpdater("containd")
	ip := net.ParseIP("10.1.2.3")
	args := u.buildBlockHostArgs(ip, 5*time.Second)
	joined := strings.Join(args, " ")
	if !strings.Contains(joined, "block_hosts") || !strings.Contains(joined, "10.1.2.3 timeout 5s") {
		t.Fatalf("unexpected host args: %s", joined)
	}

	src := net.ParseIP("10.0.0.1")
	dst := net.ParseIP("10.0.0.2")
	fargs := u.buildBlockFlowArgs(src, dst, "502", 0)
	fjoined := strings.Join(fargs, " ")
	if !strings.Contains(fjoined, "block_flows") || !strings.Contains(fjoined, "10.0.0.1 . 10.0.0.2 . 502") {
		t.Fatalf("unexpected flow args: %s", fjoined)
	}
}
