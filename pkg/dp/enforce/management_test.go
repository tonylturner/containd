// SPDX-License-Identifier: Apache-2.0
package enforce

import (
	"net/netip"
	"strings"
	"testing"

	"github.com/tonylturner/containd/pkg/common/mgmtpath"
	"github.com/tonylturner/containd/pkg/dp/rules"
)

func TestManagementEUExample(t *testing.T) {
	r := &mgmtpath.Reservation{Device: "eth7", Local: netip.MustParsePrefix("10.99.99.2/24"), Sources: []netip.Addr{netip.MustParseAddr("10.99.99.10"), netip.MustParseAddr("10.99.99.3")}, Port: 8080}
	c := NewCompiler()
	c.ManagementReservation = r
	snap := &rules.Snapshot{Default: rules.ActionDeny, LocalInput: []rules.LocalServiceRule{{ID: "ordinary", Proto: "tcp", Port: 8443}}}
	text, err := c.CompileFirewall(snap)
	if err != nil {
		t.Fatal(err)
	}
	t.Log("EU nft ruleset:\n" + text)
	want := `iifname "eth7" ip saddr { 10.99.99.10, 10.99.99.3 } ip daddr 10.99.99.2 tcp dport 8080 accept;`
	pos := strings.Index(text, want)
	if pos < strings.Index(text, "ct state invalid drop;") || pos > strings.Index(text, "tcp dport 8443 accept;") || strings.Count(text, want) != 1 {
		t.Fatal(text)
	}
	snap.NAT.PortForwards = []rules.PortForward{{Enabled: true, Proto: "tcp", ListenPort: 8080, IngressZone: "lan"}}
	snap.ZoneIfaces = map[string][]string{"lan": {"eth7"}}
	if ValidateManagementSnapshot(snap, r) == nil {
		t.Fatal("accepted shadowing DNAT")
	}
	snap.NAT.PortForwards[0].AllowedSources = []string{"192.0.2.0/24"}
	if err := ValidateManagementSnapshot(snap, r); err != nil {
		t.Fatal(err)
	}
}
