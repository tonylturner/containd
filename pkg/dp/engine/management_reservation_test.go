// SPDX-License-Identifier: Apache-2.0
package engine

import (
	"context"
	"net/netip"
	"strings"
	"testing"

	"github.com/tonylturner/containd/pkg/common/mgmtpath"
	"github.com/tonylturner/containd/pkg/dp/enforce"
	"github.com/tonylturner/containd/pkg/dp/rules"
)

func TestProcessAuthoritySurvivesReconfigure(t *testing.T) {
	r := &mgmtpath.Reservation{Device: "eth7", Local: netip.MustParsePrefix("10.99.99.2/24"), Sources: []netip.Addr{netip.MustParseAddr("10.99.99.10")}, Port: 8080}
	if _, err := New(Config{Enforce: EnforceConfig{ClearMark: noPolicyMarks, ManagementReservation: r}}); err == nil {
		t.Fatal("accepted disabled enforcement")
	}
	api := &enforce.EngineAPIPath{Device: "eth6", Addr: netip.MustParseAddr("10.98.0.2"), Port: 9091}
	cfg := Config{Enforce: EnforceConfig{ClearMark: noPolicyMarks, Enabled: true, ManagementReservation: r, EngineAPI: api}}
	e, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	applier := &recordingApplier{}
	fresh, err := New(Config{Events: e.Events(), Enforce: EnforceConfig{ClearMark: noPolicyMarks, Enabled: true, Applier: applier}})
	if err != nil {
		t.Fatal(err)
	}
	e.Reconfigure(fresh)
	text, err := e.compiler.CompileFirewall(&rules.Snapshot{})
	if err != nil || !strings.Contains(text, "ip daddr 10.99.99.2 tcp dport 8080 accept") ||
		!strings.Contains(text, `iifname "eth6" ip daddr 10.98.0.2 tcp dport 9091 accept`) {
		t.Fatal(text, err)
	}
	before := e.CurrentRules()
	snap := rules.Snapshot{NAT: rules.NATConfig{PortForwards: []rules.PortForward{{Enabled: true, Proto: "tcp", ListenPort: 8080, IngressZone: "lan"}}}, ZoneIfaces: map[string][]string{"lan": {"eth7"}}}
	if err := e.ApplyRules(context.Background(), snap); err == nil {
		t.Fatal("accepted DNAT shadow")
	}
	if e.CurrentRules() != before {
		t.Fatal("rejected rules swapped snapshot")
	}
	if applier.ruleset != "" {
		t.Fatal("rejected rules touched the kernel applier")
	}
	snap.NAT.PortForwards[0].AllowedSources = []string{"192.0.2.0/24"}
	snap.NAT.PortForwards[0].DestIP = "192.0.2.2"
	if err := e.ApplyRules(context.Background(), snap); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(applier.ruleset, "ip daddr 10.99.99.2 tcp dport 8080 accept") {
		t.Fatal("accepted reconstruction lost reserved allow")
	}
}
